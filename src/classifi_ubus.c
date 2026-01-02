/*
 * classifi - eBPF + nDPI traffic classifier
 * Copyright (C) 2025 Chad Monroe <chad@monroe.io>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <regex.h>
#include <libubox/blobmsg.h>
#include <libubus.h>
#include <uci.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <linux/in.h>
#include <ndpi/ndpi_api.h>

#include "classifi_ubus.h"

static struct classifi_ctx *g_ctx;

static const char *
uci_get_option_string(struct uci_section *s, const char *option)
{
	struct uci_option *o;
	struct uci_element *e;

	uci_foreach_element(&s->options, e) {
		o = uci_to_option(e);
		if (strcmp(o->e.name, option) == 0 && o->type == UCI_TYPE_STRING)
			return o->v.string;
	}
	return NULL;
}

int
discover_interfaces_from_uci(const char **iface_names, int max_ifaces)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;
	struct uci_section *s;
	const char *proto, *device, *name, *disabled, *ifname;
	int count = 0;

	ctx = uci_alloc_context();
	if (!ctx) {
		fprintf(stderr, "failed to allocate UCI context for interface discovery\n");
		return 0;
	}

	if (uci_load(ctx, "network", &pkg) != UCI_OK) {
		fprintf(stderr, "failed to load UCI network config\n");
		uci_free_context(ctx);
		return 0;
	}

	if (g_ctx && g_ctx->verbose)
		fprintf(stderr, "discovering LAN interfaces from UCI network configuration\n");

	uci_foreach_element(&pkg->sections, e) {
		s = uci_to_section(e);

		if (strcmp(s->type, "interface") != 0)
			continue;

		if (strncmp(s->e.name, "wan", 3) == 0)
			continue;

		if (strcmp(s->e.name, "loopback") == 0)
			continue;

		disabled = uci_get_option_string(s, "disabled");
		if (disabled && strcmp(disabled, "1") == 0)
			continue;

		proto = uci_get_option_string(s, "proto");
		if (!proto || strcmp(proto, "static") != 0)
			continue;

		device = uci_get_option_string(s, "device");
		name = uci_get_option_string(s, "name");

		if (!device && !name)
			continue;

		ifname = name ? name : device;

		if (count >= max_ifaces) {
			fprintf(stderr, "too many interfaces discovered (max %d)\n", max_ifaces);
			break;
		}

		iface_names[count] = strdup(ifname);
		if (!iface_names[count]) {
			fprintf(stderr, "failed to allocate interface name\n");
			for (int j = 0; j < count; j++)
				free((void *)iface_names[j]);
			count = 0;
			break;
		}

		if (g_ctx && g_ctx->verbose)
			fprintf(stderr, "discovered interface: %s -> %s\n", s->e.name, ifname);

		count++;
	}

	uci_unload(ctx, pkg);
	uci_free_context(ctx);

	return count;
}

void
rules_free(struct classifi_ctx *ctx)
{
	struct classifi_rule *rule = ctx->rules;

	while (rule) {
		struct classifi_rule *next = rule->next;

		if (rule->regex_compiled)
			regfree(&rule->regex);
		free(rule);
		rule = next;
	}

	ctx->rules = NULL;
	ctx->num_rules = 0;
}

int
rules_load_from_uci(struct classifi_ctx *ctx)
{
	struct uci_context *uci;
	struct uci_package *pkg;
	struct uci_element *e;
	struct uci_section *s;
	const char *name, *dst_ip, *dst_port_str, *protocol, *pattern, *script;
	const char *enabled, *host_header;
	struct classifi_rule *rule, *tail = NULL;
	int count = 0;

	rules_free(ctx);

	uci = uci_alloc_context();
	if (!uci) {
		fprintf(stderr, "failed to allocate UCI context for rules\n");
		return -1;
	}

	if (uci_load(uci, "classifi", &pkg) != UCI_OK) {
		if (ctx->verbose)
			fprintf(stderr, "no classifi UCI config found, no rules loaded\n");
		uci_free_context(uci);
		return 0;
	}

	uci_foreach_element(&pkg->sections, e) {
		s = uci_to_section(e);

		if (strcmp(s->type, "rule") != 0)
			continue;

		if (count >= MAX_RULES) {
			fprintf(stderr, "maximum number of rules (%d) reached\n", MAX_RULES);
			break;
		}

		enabled = uci_get_option_string(s, "enabled");
		if (enabled && strcmp(enabled, "0") == 0)
			continue;

		name = uci_get_option_string(s, "name");
		dst_ip = uci_get_option_string(s, "dst_ip");
		dst_port_str = uci_get_option_string(s, "dst_port");
		pattern = uci_get_option_string(s, "pattern");
		host_header = uci_get_option_string(s, "host_header");

		if (!name || !dst_port_str || !pattern) {
			fprintf(stderr, "rule '%s' missing required fields (name, dst_port, pattern)\n",
				s->e.name);
			continue;
		}

		if (!dst_ip && !host_header) {
			fprintf(stderr, "rule '%s' must have at least dst_ip or host_header\n",
				s->e.name);
			continue;
		}

		rule = calloc(1, sizeof(*rule));
		if (!rule) {
			fprintf(stderr, "failed to allocate rule\n");
			continue;
		}

		snprintf(rule->name, sizeof(rule->name), "%s", name);
		rule->enabled = 1;
		rule->dst_port = (__u16)atoi(dst_port_str);

		if (dst_ip) {
			if (inet_pton(AF_INET, dst_ip, &rule->dst_ip.lo) == 1) {
				rule->dst_family = FLOW_FAMILY_IPV4;
				rule->dst_ip.hi = 0;
				rule->has_dst_ip = 1;
			} else if (inet_pton(AF_INET6, dst_ip, &rule->dst_ip) == 1) {
				rule->dst_family = FLOW_FAMILY_IPV6;
				rule->has_dst_ip = 1;
			} else {
				fprintf(stderr, "rule '%s': invalid dst_ip '%s'\n", name, dst_ip);
				free(rule);
				continue;
			}
		}

		if (host_header)
			snprintf(rule->host_header, sizeof(rule->host_header), "%s", host_header);

		protocol = uci_get_option_string(s, "protocol");
		if (!protocol || strcmp(protocol, "tcp") == 0)
			rule->protocol = IPPROTO_TCP;
		else if (strcmp(protocol, "udp") == 0)
			rule->protocol = IPPROTO_UDP;
		else {
			fprintf(stderr, "rule '%s': unknown protocol '%s', using tcp\n", name, protocol);
			rule->protocol = IPPROTO_TCP;
		}

		snprintf(rule->pattern, sizeof(rule->pattern), "%s", pattern);
		if (regcomp(&rule->regex, pattern, REG_EXTENDED) != 0) {
			fprintf(stderr, "rule '%s': failed to compile pattern '%s'\n", name, pattern);
			free(rule);
			continue;
		}
		rule->regex_compiled = 1;

		script = uci_get_option_string(s, "script");
		if (script)
			snprintf(rule->script, sizeof(rule->script), "%s", script);

		if (!ctx->rules)
			ctx->rules = rule;
		else
			tail->next = rule;
		tail = rule;
		count++;

		if (ctx->verbose) {
			char ip_str[INET6_ADDRSTRLEN] = "any";
			if (rule->has_dst_ip) {
				if (rule->dst_family == FLOW_FAMILY_IPV4) {
					uint32_t ip = (uint32_t)rule->dst_ip.lo;
					inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
				} else {
					inet_ntop(AF_INET6, &rule->dst_ip, ip_str, sizeof(ip_str));
				}
			}
			fprintf(stderr, "loaded rule '%s': %s:%u%s%s pattern='%s'%s\n",
				rule->name, ip_str, rule->dst_port,
				rule->host_header[0] ? " host=" : "",
				rule->host_header[0] ? rule->host_header : "",
				rule->pattern,
				rule->script[0] ? " (with script)" : "");
		}
	}

	uci_unload(uci, pkg);
	uci_free_context(uci);

	ctx->num_rules = count;
	printf("loaded %d rule(s) from UCI config\n", count);

	return count;
}

static struct interface_info *
interface_by_name(struct classifi_ctx *ctx, const char *name)
{
	for (int i = 0; i < ctx->num_interfaces; i++) {
		if (ctx->interfaces[i].name && strcmp(ctx->interfaces[i].name, name) == 0)
			return &ctx->interfaces[i];
	}
	return NULL;
}

static int
detach_interface(struct classifi_ctx *ctx, struct interface_info *iface)
{
	LIBBPF_OPTS(bpf_tc_hook, hook);
	LIBBPF_OPTS(bpf_tc_opts, opts);
	int ret, idx;

	if (!iface || !iface->ifindex || !iface->name)
		return -1;

	hook.ifindex = iface->ifindex;
	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

	hook.attach_point = BPF_TC_INGRESS;
	opts.handle = iface->tc_handle_ingress;
	opts.priority = iface->tc_priority_ingress;
	ret = bpf_tc_detach(&hook, &opts);
	if (ret && ret != -ENOENT)
		fprintf(stderr, "warning: failed to detach TC program from %s ingress: %s\n",
			iface->name, strerror(-ret));

	hook.attach_point = BPF_TC_EGRESS;
	opts.handle = iface->tc_handle_egress;
	opts.priority = iface->tc_priority_egress;
	ret = bpf_tc_detach(&hook, &opts);
	if (ret && ret != -ENOENT)
		fprintf(stderr, "warning: failed to detach TC program from %s egress: %s\n",
			iface->name, strerror(-ret));

	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
	bpf_tc_hook_destroy(&hook);

	printf("detached BPF program from %s (ifindex %d)\n", iface->name, iface->ifindex);

	if (iface->discovered && iface->name) {
		free((void *)iface->name);
		iface->name = NULL;
	}

	idx = iface - ctx->interfaces;
	if (idx >= 0 && idx < ctx->num_interfaces) {
		memmove(&ctx->interfaces[idx], &ctx->interfaces[idx + 1],
			(ctx->num_interfaces - idx - 1) * sizeof(struct interface_info));
		ctx->num_interfaces--;
		memset(&ctx->interfaces[ctx->num_interfaces], 0, sizeof(struct interface_info));
	}

	return 0;
}

static int
attach_tc_program(struct classifi_ctx *ctx, int prog_fd,
		  const char *ifname, int discovered)
{
	int ifindex;
	LIBBPF_OPTS(bpf_tc_hook, hook);
	LIBBPF_OPTS(bpf_tc_opts, opts_ingress);
	LIBBPF_OPTS(bpf_tc_opts, opts_egress);
	int ret;

	if (ctx->num_interfaces >= MAX_INTERFACES) {
		fprintf(stderr, "maximum number of interfaces (%d) reached\n", MAX_INTERFACES);
		return -1;
	}

	if (interface_by_name(ctx, ifname)) {
		if (ctx->verbose)
			fprintf(stderr, "interface %s already attached, skipping\n", ifname);
		return 0;
	}

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "failed to get ifindex for %s: %s\n",
			ifname, strerror(errno));
		return -1;
	}

	hook.ifindex = ifindex;
	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

	bpf_tc_hook_destroy(&hook);

	ret = bpf_tc_hook_create(&hook);
	if (ret && ret != -EEXIST) {
		fprintf(stderr, "failed to create TC hook for %s: %s\n", ifname, strerror(-ret));
		return ret;
	}

	hook.attach_point = BPF_TC_INGRESS;
	opts_ingress.prog_fd = prog_fd;
	opts_ingress.flags = BPF_TC_F_REPLACE;
	ret = bpf_tc_attach(&hook, &opts_ingress);
	if (ret) {
		fprintf(stderr, "failed to attach TC program to %s ingress: %s\n", ifname, strerror(-ret));
		return ret;
	}

	hook.attach_point = BPF_TC_EGRESS;
	opts_egress.prog_fd = prog_fd;
	opts_egress.flags = BPF_TC_F_REPLACE;
	ret = bpf_tc_attach(&hook, &opts_egress);
	if (ret) {
		fprintf(stderr, "failed to attach TC program to %s egress: %s\n", ifname, strerror(-ret));
		hook.attach_point = BPF_TC_INGRESS;
		bpf_tc_detach(&hook, &opts_ingress);
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&hook);
		return ret;
	}

	printf("attached BPF program to %s ingress+egress (ifindex %d)\n", ifname, ifindex);

	ctx->interfaces[ctx->num_interfaces].name = ifname;
	ctx->interfaces[ctx->num_interfaces].ifindex = ifindex;
	ctx->interfaces[ctx->num_interfaces].discovered = discovered;
	ctx->interfaces[ctx->num_interfaces].tc_handle_ingress = opts_ingress.handle;
	ctx->interfaces[ctx->num_interfaces].tc_priority_ingress = opts_ingress.priority;
	ctx->interfaces[ctx->num_interfaces].tc_handle_egress = opts_egress.handle;
	ctx->interfaces[ctx->num_interfaces].tc_priority_egress = opts_egress.priority;
	ctx->num_interfaces++;

	return 0;
}

int get_interface_ip(struct interface_info *iface);

int
reload_config(struct classifi_ctx *ctx, int *out_added, int *out_removed)
{
	const char *discovered[MAX_INTERFACES];
	int num_discovered;
	int added = 0, removed = 0;

	if (ctx->bpf_prog_fd < 0) {
		fprintf(stderr, "cannot reload: BPF program not loaded\n");
		return -1;
	}

	num_discovered = discover_interfaces_from_uci(discovered, MAX_INTERFACES);
	if (num_discovered == 0) {
		fprintf(stderr, "no interfaces discovered during reload\n");
		return 0;
	}

	for (int i = ctx->num_interfaces - 1; i >= 0; i--) {
		struct interface_info *iface = &ctx->interfaces[i];
		int found = 0;

		if (!iface->discovered)
			continue;

		for (int j = 0; j < num_discovered; j++) {
			if (discovered[j] && strcmp(iface->name, discovered[j]) == 0) {
				found = 1;
				break;
			}
		}

		if (!found) {
			printf("removing interface %s (no longer in UCI config)\n", iface->name);
			detach_interface(ctx, iface);
			removed++;
		}
	}

	for (int i = 0; i < num_discovered; i++) {
		if (!discovered[i])
			continue;

		if (interface_by_name(ctx, discovered[i])) {
			free((void *)discovered[i]);
			continue;
		}

		if (attach_tc_program(ctx, ctx->bpf_prog_fd, discovered[i], 1) == 0) {
			get_interface_ip(&ctx->interfaces[ctx->num_interfaces - 1]);
			printf("added interface %s\n", discovered[i]);
			added++;
		} else {
			free((void *)discovered[i]);
		}
	}

	printf("config reload: %d added, %d removed, %d total\n",
	       added, removed, ctx->num_interfaces);

	rules_load_from_uci(ctx);

	if (out_added)
		*out_added = added;
	if (out_removed)
		*out_removed = removed;

	return 0;
}

struct flow_blob_ctx {
	struct blob_buf *b;
	int count;
};

static void
flow_key_to_strings(const struct flow_key *key,
		    char *src_ip, size_t src_len,
		    char *dst_ip, size_t dst_len)
{
	if (key->family == FLOW_FAMILY_IPV4) {
		struct in_addr src = { .s_addr = (__u32)key->src.lo };
		struct in_addr dst = { .s_addr = (__u32)key->dst.lo };

		inet_ntop(AF_INET, &src, src_ip, src_len);
		inet_ntop(AF_INET, &dst, dst_ip, dst_len);
	} else if (key->family == FLOW_FAMILY_IPV6) {
		struct in6_addr src6, dst6;

		memcpy(&src6, &key->src, sizeof(src6));
		memcpy(&dst6, &key->dst, sizeof(dst6));
		inet_ntop(AF_INET6, &src6, src_ip, src_len);
		inet_ntop(AF_INET6, &dst6, dst_ip, dst_len);
	} else {
		snprintf(src_ip, src_len, "unknown");
		snprintf(dst_ip, dst_len, "unknown");
	}
}

static void
flow_to_blob(struct classifi_ctx *ctx, struct ndpi_flow *flow, void *user_data)
{
	struct flow_blob_ctx *fbc = user_data;
	struct blob_buf *b = fbc->b;
	void *flow_obj, *stack_array;
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	const char *master_name, *app_name, *category_name;
	struct flow_key display_key;
	uint64_t now = monotonic_time_sec();

	if (flow->have_first_packet_key)
		display_key = flow->first_packet_key;
	else
		display_key = flow->key;

	flow_key_to_strings(&display_key, src_ip, sizeof(src_ip),
			    dst_ip, sizeof(dst_ip));

	if (flow->protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
		master_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.app_protocol);
	else
		master_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.master_protocol);
	app_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.app_protocol);
	category_name = ndpi_category_get_name(ctx->ndpi, flow->protocol.category);

	flow_obj = blobmsg_open_table(b, NULL);

	blobmsg_add_string(b, "src_ip", src_ip);
	blobmsg_add_u32(b, "src_port", display_key.src_port);
	blobmsg_add_string(b, "dst_ip", dst_ip);
	blobmsg_add_u32(b, "dst_port", display_key.dst_port);
	blobmsg_add_u32(b, "protocol", display_key.protocol);
	blobmsg_add_string(b, "family", display_key.family == FLOW_FAMILY_IPV4 ? "ipv4" : "ipv6");

	blobmsg_add_string(b, "master_protocol", master_name);
	blobmsg_add_string(b, "app_protocol", app_name);
	blobmsg_add_string(b, "category", category_name);

	blobmsg_add_u32(b, "packets", flow->packets_processed);
	blobmsg_add_u32(b, "packets_tx", flow->packets_dir0);
	blobmsg_add_u32(b, "packets_rx", flow->packets_dir1);

	blobmsg_add_u32(b, "age", now - flow->first_seen);
	blobmsg_add_u32(b, "idle_time", now - flow->last_seen);

	blobmsg_add_u8(b, "classified", flow->detection_finalized);
	blobmsg_add_u8(b, "guessed", flow->protocol_guessed);

	if (flow->tcp_fingerprint[0])
		blobmsg_add_string(b, "tcp_fingerprint", flow->tcp_fingerprint);
	if (flow->os_hint[0])
		blobmsg_add_string(b, "os_hint", flow->os_hint);

	if (flow->protocol_stack_count > 1) {
		int stack_count = flow->protocol_stack_count;
		if (stack_count > 8)
			stack_count = 8;
		stack_array = blobmsg_open_array(b, "protocol_stack");
		for (int j = 0; j < stack_count; j++)
			blobmsg_add_string(b, NULL, ndpi_get_proto_name(ctx->ndpi, flow->protocol_stack[j]));
		blobmsg_close_array(b, stack_array);
	}

	blobmsg_close_table(b, flow_obj);
	fbc->count++;
}

static int
classifi_reload_config_handler(struct ubus_context *uctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg)
{
	struct blob_buf b = {};
	int added = 0, removed = 0;
	int ret;

	(void)obj;
	(void)method;
	(void)msg;

	ret = reload_config(g_ctx, &added, &removed);

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "added", added);
	blobmsg_add_u32(&b, "removed", removed);
	blobmsg_add_u32(&b, "interfaces", g_ctx->num_interfaces);
	ubus_send_reply(uctx, req, b.head);
	blob_buf_free(&b);

	return ret == 0 ? UBUS_STATUS_OK : UBUS_STATUS_UNKNOWN_ERROR;
}

static int
classifi_status_handler(struct ubus_context *uctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_buf b = {};
	void *ifaces, *iface_obj;
	char ip_str[INET6_ADDRSTRLEN];
	__u32 stats_key = 0;
	__u64 drops = 0;

	(void)obj;
	(void)method;
	(void)msg;

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "mode", g_ctx->pcap_mode ? "pcap" : "ebpf");
	blobmsg_add_u8(&b, "verbose", g_ctx->verbose);
	blobmsg_add_u8(&b, "periodic_stats", g_ctx->periodic_stats);

	if (g_ctx->ringbuf_stats_fd >= 0)
		bpf_map_lookup_elem(g_ctx->ringbuf_stats_fd, &stats_key, &drops);
	blobmsg_add_u64(&b, "ringbuf_drops", drops);

	ifaces = blobmsg_open_array(&b, "interfaces");
	for (int i = 0; i < g_ctx->num_interfaces; i++) {
		struct interface_info *info = &g_ctx->interfaces[i];

		iface_obj = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "name", info->name ? info->name : "");
		blobmsg_add_u32(&b, "ifindex", info->ifindex);
		blobmsg_add_u8(&b, "discovered", info->discovered);

		if (info->local_ip_family == FLOW_FAMILY_IPV4) {
			uint32_t ip = (uint32_t)info->local_ip.lo;
			inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
			blobmsg_add_string(&b, "local_ip", ip_str);
			blobmsg_add_string(&b, "family", "ipv4");
		} else if (info->local_ip_family == FLOW_FAMILY_IPV6) {
			struct in6_addr addr;
			memcpy(&addr, &info->local_ip, sizeof(addr));
			inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));
			blobmsg_add_string(&b, "local_ip", ip_str);
			blobmsg_add_string(&b, "family", "ipv6");
		}

		blobmsg_close_table(&b, iface_obj);
	}
	blobmsg_close_array(&b, ifaces);

	void *rules = blobmsg_open_array(&b, "rules");
	struct classifi_rule *rule;
	for (rule = g_ctx->rules; rule; rule = rule->next) {
		void *rule_obj = blobmsg_open_table(&b, NULL);

		blobmsg_add_string(&b, "name", rule->name);
		blobmsg_add_u8(&b, "enabled", rule->enabled);

		if (rule->has_dst_ip) {
			if (rule->dst_family == FLOW_FAMILY_IPV4) {
				uint32_t ip = (uint32_t)rule->dst_ip.lo;
				inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
			} else {
				struct in6_addr addr;
				memcpy(&addr, &rule->dst_ip, sizeof(addr));
				inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));
			}
			blobmsg_add_string(&b, "dst_ip", ip_str);
		}

		if (rule->host_header[0])
			blobmsg_add_string(&b, "host_header", rule->host_header);

		blobmsg_add_u32(&b, "dst_port", rule->dst_port);
		blobmsg_add_string(&b, "protocol", rule->protocol == IPPROTO_TCP ? "tcp" : "udp");
		blobmsg_add_string(&b, "pattern", rule->pattern);

		if (rule->script[0])
			blobmsg_add_string(&b, "script", rule->script);

		blobmsg_add_u64(&b, "hits", rule->hits);

		blobmsg_close_table(&b, rule_obj);
	}
	blobmsg_close_array(&b, rules);

	blobmsg_add_u32(&b, "num_rules", g_ctx->num_rules);

	ubus_send_reply(uctx, req, b.head);
	blob_buf_free(&b);

	return UBUS_STATUS_OK;
}

static int
classifi_get_flows_handler(struct ubus_context *uctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct blob_buf b = {};
	struct flow_blob_ctx fbc = { .b = &b, .count = 0 };
	void *flows_array;

	(void)obj;
	(void)method;
	(void)msg;

	blob_buf_init(&b, 0);
	flows_array = blobmsg_open_array(&b, "flows");
	flow_table_iterate(g_ctx, flow_to_blob, &fbc);
	blobmsg_close_array(&b, flows_array);
	blobmsg_add_u32(&b, "count", fbc.count);

	ubus_send_reply(uctx, req, b.head);
	blob_buf_free(&b);

	return UBUS_STATUS_OK;
}

static const struct ubus_method classifi_methods[] = {
	UBUS_METHOD_NOARG("reload_config", classifi_reload_config_handler),
	UBUS_METHOD_NOARG("status", classifi_status_handler),
	UBUS_METHOD_NOARG("get_flows", classifi_get_flows_handler),
};

static struct ubus_object_type classifi_obj_type =
	UBUS_OBJECT_TYPE("classifi", classifi_methods);

static struct ubus_object classifi_obj = {
	.name = "classifi",
	.type = &classifi_obj_type,
	.methods = classifi_methods,
	.n_methods = ARRAY_SIZE(classifi_methods),
};

int
classifi_ubus_init(struct classifi_ctx *ctx)
{
	if (!ctx || !ctx->ubus_ctx)
		return -1;

	g_ctx = ctx;

	if (ubus_add_object(ctx->ubus_ctx, &classifi_obj) != 0) {
		fprintf(stderr, "failed to add classifi ubus object\n");
		return -1;
	}

	if (ctx->verbose)
		fprintf(stderr, "registered classifi ubus object\n");

	return 0;
}
