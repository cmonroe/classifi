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
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <ndpi/ndpi_api.h>
/* Prevent pcap/bpf.h inclusion to avoid conflicts with libbpf */
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubus.h>

#include "classifi.h"
#include "classifi_ubus.h"

#define TICK_RESOLUTION 1000

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define FLOW_IDLE_TIMEOUT 30
#define FLOW_ABSOLUTE_TIMEOUT 60
#define CLEANUP_INTERVAL 30

static volatile int keep_running = 1;

static struct interface_info *interface_by_index(struct classifi_ctx *ctx, int ifindex)
{
	for (int i = 0; i < ctx->num_interfaces; i++) {
		if (ctx->interfaces[i].ifindex == ifindex)
			return &ctx->interfaces[i];
	}
	return NULL;
}

static const char *interface_name_by_index(struct classifi_ctx *ctx, int ifindex)
{
	struct interface_info *iface = interface_by_index(ctx, ifindex);
	return iface ? iface->name : "unknown";
}

struct interface_info *interface_by_name(struct classifi_ctx *ctx, const char *name)
{
	for (int i = 0; i < ctx->num_interfaces; i++) {
		if (ctx->interfaces[i].name && strcmp(ctx->interfaces[i].name, name) == 0)
			return &ctx->interfaces[i];
	}
	return NULL;
}

static void cleanup_flow_table(struct classifi_ctx *ctx)
{
	for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
		struct ndpi_flow *flow = ctx->flow_table[i];
		while (flow) {
			struct ndpi_flow *next = flow->next;
			if (flow->flow)
				ndpi_flow_free(flow->flow);
			free(flow);
			flow = next;
		}
		ctx->flow_table[i] = NULL;
	}
}

static void cleanup_dns_table(struct classifi_ctx *ctx)
{
	for (int i = 0; i < DNS_TABLE_SIZE; i++) {
		struct dns_stats *stats = ctx->dns_table[i];
		while (stats) {
			struct dns_stats *next = stats->next;
			free(stats);
			stats = next;
		}
		ctx->dns_table[i] = NULL;
	}
}

#define FNV_OFFSET 2166136261u
#define FNV_PRIME 16777619u

static inline unsigned int fnv_mix64(unsigned int hash, __u64 value)
{
	hash ^= (unsigned int)(value >> 32);
	hash *= FNV_PRIME;
	hash ^= (unsigned int)value;
	hash *= FNV_PRIME;
	return hash;
}

static int extract_dns_query_name(const unsigned char *dns_payload, unsigned int len, char *out, size_t out_len)
{
	unsigned int pos = 12;
	unsigned int out_pos = 0;

	if (len < 12)
		return -1;

	while (pos < len && out_pos < out_len - 1) {
		unsigned char label_len = dns_payload[pos];

		if (label_len == 0) {
			if (out_pos > 0)
				out[out_pos - 1] = '\0';
			else
				out[0] = '\0';
			return 0;
		}

		/* Compression pointer - not expected in queries */
		if (label_len >= 0xC0)
			break;

		if (label_len > 63 || pos + 1 + label_len > len)
			break;

		pos++;
		for (unsigned int i = 0; i < label_len && out_pos < out_len - 2; i++) {
			out[out_pos++] = dns_payload[pos++];
		}
		out[out_pos++] = '.';
	}

	out[0] = '\0';
	return -1;
}

static unsigned int dns_hash(struct flow_addr *addr, __u8 family)
{
	unsigned int hash = FNV_OFFSET;
	hash ^= family;
	hash *= FNV_PRIME;
	hash = fnv_mix64(hash, addr->hi);
	hash = fnv_mix64(hash, addr->lo);
	return hash % DNS_TABLE_SIZE;
}

static struct dns_stats *dns_lookup(struct classifi_ctx *ctx, struct flow_addr *addr, __u8 family)
{
	unsigned int hash = dns_hash(addr, family);
	struct dns_stats *stats = ctx->dns_table[hash];

	while (stats) {
		if (stats->family == family &&
		    stats->client_ip.hi == addr->hi &&
		    stats->client_ip.lo == addr->lo)
			return stats;
		stats = stats->next;
	}
	return NULL;
}

static struct dns_stats *dns_insert(struct classifi_ctx *ctx, struct flow_addr *addr, __u8 family)
{
	unsigned int hash = dns_hash(addr, family);
	struct dns_stats *stats = calloc(1, sizeof(*stats));

	if (!stats)
		return NULL;

	stats->family = family;
	stats->client_ip = *addr;
	stats->next = ctx->dns_table[hash];
	ctx->dns_table[hash] = stats;

	return stats;
}

static unsigned int flow_hash(struct flow_key *key)
{
	unsigned int hash = FNV_OFFSET;
	hash ^= key->family;
	hash *= FNV_PRIME;
	hash ^= key->protocol;
	hash *= FNV_PRIME;
	hash ^= ((unsigned int)key->src_port << 16) | key->dst_port;
	hash *= FNV_PRIME;
	hash = fnv_mix64(hash, key->src.hi);
	hash = fnv_mix64(hash, key->src.lo);
	hash = fnv_mix64(hash, key->dst.hi);
	hash = fnv_mix64(hash, key->dst.lo);
	return hash % FLOW_TABLE_SIZE;
}

static int flow_key_equal(struct flow_key *a, struct flow_key *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static struct ndpi_flow *flow_table_lookup(struct classifi_ctx *ctx, struct flow_key *key)
{
	unsigned int hash = flow_hash(key);
	struct ndpi_flow *flow = ctx->flow_table[hash];

	while (flow) {
		if (flow_key_equal(&flow->key, key))
			return flow;
		flow = flow->next;
	}
	return NULL;
}

static void swap_flow_endpoints(struct flow_key *key)
{
	__u16 tmp_port = key->src_port;
	__u64 tmp_hi = key->src.hi;
	__u64 tmp_lo = key->src.lo;
	key->src_port = key->dst_port;
	key->dst_port = tmp_port;
	key->src.hi = key->dst.hi;
	key->src.lo = key->dst.lo;
	key->dst.hi = tmp_hi;
	key->dst.lo = tmp_lo;
}

static void flow_key_to_strings(const struct flow_key *key,
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

static struct ndpi_flow *flow_table_insert(struct classifi_ctx *ctx, struct flow_key *key)
{
	unsigned int hash = flow_hash(key);
	struct ndpi_flow *flow = calloc(1, sizeof(*flow));

	if (!flow)
		return NULL;

	memcpy(&flow->key, key, sizeof(*key));
	flow->flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);

	if (!flow->flow) {
		free(flow);
		return NULL;
	}

	memset(flow->flow, 0, SIZEOF_FLOW_STRUCT);

	flow->first_seen = time(NULL);
	flow->last_seen = flow->first_seen;

	flow->next = ctx->flow_table[hash];
	ctx->flow_table[hash] = flow;

	return flow;
}

struct vlan_hdr {
	__u16 h_vlan_TCI;
	__u16 h_vlan_encapsulated_proto;
} __attribute__((packed));

static int parse_packet_libpcap(const unsigned char *packet, int packet_len,
				struct flow_key *key, unsigned char **l3_data,
				unsigned int *l3_len, __u8 *direction)
{
	const struct ethhdr *eth;
	__u16 eth_type;
	const unsigned char *ptr;
	int offset = 0;
	int i;

	if (packet_len < sizeof(struct ethhdr))
		return -1;

	eth = (struct ethhdr *)packet;
	eth_type = ntohs(eth->h_proto);
	offset = sizeof(struct ethhdr);
	ptr = packet + offset;

	for (i = 0; i < 2; i++) {
		if (eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD) {
			const struct vlan_hdr *vlan;

			if (offset + sizeof(struct vlan_hdr) > packet_len)
				return -1;

			vlan = (struct vlan_hdr *)ptr;
			eth_type = ntohs(vlan->h_vlan_encapsulated_proto);
			offset += sizeof(struct vlan_hdr);
			ptr = packet + offset;
		}
	}

	memset(key, 0, sizeof(*key));

	if (eth_type == ETH_P_IP) {
		const struct iphdr *iph;
		unsigned int ip_hdr_len;

		if (offset + sizeof(struct iphdr) > packet_len)
			return -1;

		iph = (struct iphdr *)ptr;
		ip_hdr_len = iph->ihl * 4;

		if (ip_hdr_len < sizeof(struct iphdr))
			return -1;
		if (offset + ip_hdr_len > packet_len)
			return -1;

		key->family = FLOW_FAMILY_IPV4;
		key->protocol = iph->protocol;
		key->src.hi = 0;
		key->src.lo = (__u64)iph->saddr;
		key->dst.hi = 0;
		key->dst.lo = (__u64)iph->daddr;

		*l3_data = (unsigned char *)ptr;
		*l3_len = packet_len - offset;

		offset += ip_hdr_len;
		ptr = packet + offset;

		if (iph->protocol == IPPROTO_TCP) {
			const struct tcphdr *tcph;

			if (offset + sizeof(struct tcphdr) > packet_len)
				return 0;

			tcph = (struct tcphdr *)ptr;
			key->src_port = ntohs(tcph->source);
			key->dst_port = ntohs(tcph->dest);
		} else if (iph->protocol == IPPROTO_UDP) {
			const struct udphdr *udph;

			if (offset + sizeof(struct udphdr) > packet_len)
				return 0;

			udph = (struct udphdr *)ptr;
			key->src_port = ntohs(udph->source);
			key->dst_port = ntohs(udph->dest);
		}

		return 0;
	}

	if (eth_type == ETH_P_IPV6) {
		const struct ipv6hdr *ip6h;

		if (offset + sizeof(struct ipv6hdr) > packet_len)
			return -1;

		ip6h = (struct ipv6hdr *)ptr;

		key->family = FLOW_FAMILY_IPV6;
		key->protocol = ip6h->nexthdr;
		memcpy(&key->src, &ip6h->saddr, sizeof(struct in6_addr));
		memcpy(&key->dst, &ip6h->daddr, sizeof(struct in6_addr));

		*l3_data = (unsigned char *)ptr;
		*l3_len = packet_len - offset;

		offset += sizeof(struct ipv6hdr);
		ptr = packet + offset;

		if (ip6h->nexthdr == IPPROTO_TCP) {
			const struct tcphdr *tcph;

			if (offset + sizeof(struct tcphdr) > packet_len)
				return 0;

			tcph = (struct tcphdr *)ptr;
			key->src_port = ntohs(tcph->source);
			key->dst_port = ntohs(tcph->dest);
		} else if (ip6h->nexthdr == IPPROTO_UDP) {
			const struct udphdr *udph;

			if (offset + sizeof(struct udphdr) > packet_len)
				return 0;

			udph = (struct udphdr *)ptr;
			key->src_port = ntohs(udph->source);
			key->dst_port = ntohs(udph->dest);
		}

		return 0;
	}

	return -1;
}

static __u8 canonicalize_flow_key_libpcap(struct flow_key *key)
{
	__u8 swapped = 0;

	if (key->family == FLOW_FAMILY_IPV4) {
		__u32 src = (__u32)key->src.lo;
		__u32 dst = (__u32)key->dst.lo;

		if (src > dst)
			swapped = 1;
		else if (src == dst && key->src_port > key->dst_port)
			swapped = 1;
	} else if (key->family == FLOW_FAMILY_IPV6) {
		if (key->src.hi > key->dst.hi)
			swapped = 1;
		else if (key->src.hi == key->dst.hi && key->src.lo > key->dst.lo)
			swapped = 1;
		else if (key->src.hi == key->dst.hi && key->src.lo == key->dst.lo &&
			 key->src_port > key->dst_port)
			swapped = 1;
	} else {
		if (key->src_port > key->dst_port)
			swapped = 1;
	}

	if (swapped)
		swap_flow_endpoints(key);

	return swapped;
}

static void signal_handler(int sig)
{
	keep_running = 0;
	uloop_end();
}

static void setup_signals(void)
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
}

int get_interface_ip(struct interface_info *iface)
{
	struct ifaddrs *ifaddr, *ifa;
	int found = 0;

	if (getifaddrs(&ifaddr) == -1) {
		fprintf(stderr, "failed to get interface addresses: %s\n", strerror(errno));
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, iface->name) == 0) {
			if (ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
				struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

				iface->local_ip_family = FLOW_FAMILY_IPV4;
				iface->local_ip.hi = 0;
				iface->local_ip.lo = (__u64)addr->sin_addr.s_addr;

				if (netmask)
					iface->local_subnet_mask = netmask->sin_addr.s_addr;

				found = 1;

				char ip_str[INET_ADDRSTRLEN];
				char mask_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));

				if (netmask) {
					inet_ntop(AF_INET, &netmask->sin_addr, mask_str, sizeof(mask_str));
					printf("interface %s IPv4: %s/%s\n",
						iface->name, ip_str, mask_str);
				} else {
					printf("interface %s IPv4: %s\n",
						iface->name, ip_str);
				}
				break;
			} else if (ifa->ifa_addr->sa_family == AF_INET6 && !found) {
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
				iface->local_ip_family = FLOW_FAMILY_IPV6;
				memcpy(&iface->local_ip, &addr6->sin6_addr, sizeof(struct in6_addr));
				found = 1;

				char ip_str[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &addr6->sin6_addr, ip_str, sizeof(ip_str));
				printf("interface %s IPv6: %s\n", iface->name, ip_str);
			}
		}
	}

	freeifaddrs(ifaddr);

	if (!found) {
		fprintf(stderr, "warning: Could not determine IP address for %s\n", iface->name);
	}

	return found ? 0 : -1;
}

static int should_filter_flow(struct classifi_ctx *ctx, struct flow_key *key)
{
	if (key->family == FLOW_FAMILY_IPV4) {
		__u32 dst_ip = (__u32)key->dst.lo;
		if (dst_ip == 0xFFFFFFFF)
			return 1;
	}

	if (key->src_port == 6379 || key->dst_port == 6379) {
		for (int i = 0; i < ctx->num_interfaces; i++) {
			struct interface_info *iface = &ctx->interfaces[i];
			if (iface->local_ip_family == 0 || key->family != iface->local_ip_family)
				continue;

			if (key->family == FLOW_FAMILY_IPV4) {
				if (key->src.lo == iface->local_ip.lo || key->dst.lo == iface->local_ip.lo)
					return 1;
			} else if (key->family == FLOW_FAMILY_IPV6) {
				if ((key->src.hi == iface->local_ip.hi && key->src.lo == iface->local_ip.lo) ||
				    (key->dst.hi == iface->local_ip.hi && key->dst.lo == iface->local_ip.lo))
					return 1;
			}
		}
	}

	return 0;
}

static void emit_classification_event(struct classifi_ctx *ctx, struct ndpi_flow *flow, const char *ifname)
{
	struct blob_buf b = {};
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	const char *master_name, *app_name, *category_name;
	struct flow_key summary_key;

	if (!ctx->ubus_ctx)
		return;

	if (flow->have_first_packet_key)
		summary_key = flow->first_packet_key;
	else
		summary_key = flow->key;

	flow_key_to_strings(&summary_key, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

	if (flow->protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
		master_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.app_protocol);
	else
		master_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.master_protocol);
	app_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.app_protocol);
	category_name = ndpi_category_get_name(ctx->ndpi, flow->protocol.category);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "interface", ifname);
	blobmsg_add_string(&b, "src_ip", src_ip);
	blobmsg_add_u32(&b, "src_port", summary_key.src_port);
	blobmsg_add_string(&b, "dst_ip", dst_ip);
	blobmsg_add_u32(&b, "dst_port", summary_key.dst_port);
	blobmsg_add_u32(&b, "protocol", summary_key.protocol);
	blobmsg_add_string(&b, "master_protocol", master_name);
	blobmsg_add_string(&b, "app_protocol", app_name);
	blobmsg_add_string(&b, "category", category_name);

	if (flow->tcp_fingerprint[0])
		blobmsg_add_string(&b, "tcp_fingerprint", flow->tcp_fingerprint);
	if (flow->os_hint[0])
		blobmsg_add_string(&b, "os_hint", flow->os_hint);

	if (flow->protocol_stack_count > 1) {
		void *stack = blobmsg_open_array(&b, "protocol_stack");
		for (int i = 0; i < flow->protocol_stack_count; i++)
			blobmsg_add_string(&b, NULL, ndpi_get_proto_name(ctx->ndpi, flow->protocol_stack[i]));
		blobmsg_close_array(&b, stack);
	}

	if (ubus_send_event(ctx->ubus_ctx, "classifi.classified", b.head) != 0) {
		if (ctx->verbose)
			fprintf(stderr, "failed to send ubus event for flow %s:%u -> %s:%u\n",
				src_ip, summary_key.src_port, dst_ip, summary_key.dst_port);
	}

	blob_buf_free(&b);
}

static struct ndpi_detection_module_struct *setup_ndpi(void)
{
	struct ndpi_detection_module_struct *ndpi_struct;

	ndpi_struct = ndpi_init_detection_module(NULL);
	if (!ndpi_struct) {
		fprintf(stderr, "failed to initialize nDPI\n");
		return NULL;
	}

	/* Fix TCP ACK payload heuristic issues (see nDPI issue #1946) */
	ndpi_set_config(ndpi_struct, NULL, "tcp_ack_payload_heuristic", "enable");

	/* We sample 50 packets, not the default 32 */
	ndpi_set_config(ndpi_struct, NULL, "packets_limit_per_flow", "50");

	ndpi_set_config(ndpi_struct, "tls", "application_blocks_tracking", "enable");
	ndpi_set_config(ndpi_struct, "dns", "subclassification", "enable");
	ndpi_set_config(ndpi_struct, NULL, "fully_encrypted_heuristic", "enable");

	/* 0x07 enables all TLS heuristics for obfuscated/proxied traffic */
	ndpi_set_config(ndpi_struct, "tls", "dpi.heuristics", "0x07");

	ndpi_set_config(ndpi_struct, NULL, "lru.tls_cert.size", "4096");
	ndpi_set_config(ndpi_struct, NULL, "lru.stun.size", "4096");
	ndpi_set_config(ndpi_struct, NULL, "lru.fpc_dns.size", "4096");
	ndpi_set_config(ndpi_struct, "any", "ip_list.load", "enable");
	ndpi_set_config(ndpi_struct, NULL, "dpi.guess_ip_before_port", "enable");
	ndpi_set_config(ndpi_struct, NULL, "hostname_dns_check", "1");
	ndpi_set_config(ndpi_struct, NULL, "metadata.tcp_fingerprint", "1");
	ndpi_set_config(ndpi_struct, "tls", "blocks_analysis", "1");

	if (ndpi_finalize_initialization(ndpi_struct) != 0) {
		fprintf(stderr, "failed to finalize nDPI initialization\n");
		ndpi_exit_detection_module(ndpi_struct);
		return NULL;
	}

	printf("initialized nDPI version %s\n",
	       ndpi_revision());

	return ndpi_struct;
}

static void classify_packet(struct classifi_ctx *ctx, struct packet_sample *sample)
{
	struct ndpi_flow *flow;
	ndpi_protocol protocol;
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	struct flow_key packet_view;
	struct ndpi_flow_input_info input_info = {0};
	static int total_samples = 0;

	total_samples++;

	if (should_filter_flow(ctx, &sample->key))
		return;

	packet_view = sample->key;
	if (sample->direction)
		swap_flow_endpoints(&packet_view);

	flow_key_to_strings(&packet_view, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

	flow = flow_table_lookup(ctx, &sample->key);
	if (!flow) {
		flow = flow_table_insert(ctx, &sample->key);
		if (!flow) {
			fprintf(stderr, "failed to create flow for %s:%u -> %s:%u\n",
				src_ip, packet_view.src_port,
				dst_ip, packet_view.dst_port);
			return;
		}
		if (ctx->verbose) {
			fprintf(stderr, "new flow: %s:%u -> %s:%u proto=%u\n",
				src_ip, packet_view.src_port,
				dst_ip, packet_view.dst_port, packet_view.protocol);
		}
	}

	if (!flow->have_first_packet_key) {
		flow->first_packet_key = packet_view;
		flow->have_first_packet_key = 1;
	}

	flow->packets_processed++;
	flow->last_seen = time(NULL);
	if (sample->direction == 0)
		flow->packets_dir0++;
	else
		flow->packets_dir1++;

	if (ctx->verbose) {
		fprintf(stderr, "sample %d (flow pkt %d, dir=%u): %s:%u -> %s:%u proto=%u len=%u l3_off=%u [dir0=%d dir1=%d]\n",
			total_samples, flow->packets_processed, sample->direction,
			src_ip, packet_view.src_port,
			dst_ip, packet_view.dst_port, packet_view.protocol,
			sample->data_len, sample->l3_offset,
			flow->packets_dir0, flow->packets_dir1);

		if (flow->packets_processed == 1 || flow->packets_processed == 2) {
			fprintf(stderr, "  packet %d hex dump (first 64 bytes):\n  ", flow->packets_processed);
			for (int i = 0; i < 64 && i < sample->data_len; i++) {
				fprintf(stderr, "%02x ", sample->data[i]);
				if ((i + 1) % 16 == 0)
					fprintf(stderr, "\n  ");
			}
			fprintf(stderr, "\n");
		}
	}

	input_info.in_pkt_dir = sample->direction ? 1 : 0;
	input_info.seen_flow_beginning = (flow->packets_processed == 1);

	unsigned int l3_offset = sample->l3_offset;
	unsigned char *ip_packet = NULL;
	unsigned int ip_packet_len = 0;

	if (l3_offset < sample->data_len) {
		ip_packet = sample->data + l3_offset;
		ip_packet_len = sample->data_len - l3_offset;
	}

	if (!ip_packet || ip_packet_len == 0) {
		if (ctx->verbose)
			fprintf(stderr, "  packet shorter than L3 offset (%u), skipping\n", l3_offset);
		return;
	}

	u_int64_t time_ms = sample->ts_ns ? sample->ts_ns / 1000000ULL : (u_int64_t)time(NULL) * 1000ULL;

	protocol = ndpi_detection_process_packet(
		ctx->ndpi, flow->flow, ip_packet, ip_packet_len,
		time_ms, &input_info);

	if (flow->flow->tcp.fingerprint && flow->flow->tcp.fingerprint[0] &&
	    !flow->tcp_fingerprint[0]) {
		snprintf(flow->tcp_fingerprint, sizeof(flow->tcp_fingerprint), "%s",
			 flow->flow->tcp.fingerprint);
		snprintf(flow->os_hint, sizeof(flow->os_hint), "%s",
			 ndpi_print_os_hint(flow->flow->tcp.os_hint));
	}

	if (protocol.protocol_stack.protos_num > 0 && flow->protocol_stack_count == 0) {
		flow->protocol_stack_count = protocol.protocol_stack.protos_num;
		for (int i = 0; i < protocol.protocol_stack.protos_num && i < 8; i++)
			flow->protocol_stack[i] = protocol.protocol_stack.protos[i];
	}

	if (ctx->verbose) {
		fprintf(stderr, "  [PKT %d] nDPI process_packet: master=%u (%s) app=%u (%s) category=%s state=%d\n",
			flow->packets_processed,
			protocol.proto.master_protocol,
			ndpi_get_proto_name(ctx->ndpi, protocol.proto.master_protocol),
			protocol.proto.app_protocol,
			ndpi_get_proto_name(ctx->ndpi, protocol.proto.app_protocol),
			ndpi_category_get_name(ctx->ndpi, protocol.category),
			protocol.state);

		if (flow->tcp_fingerprint[0]) {
			fprintf(stderr, "  [TCP FP] %s (OS: %s)\n",
				flow->tcp_fingerprint, flow->os_hint);
		}

		if (flow->protocol_stack_count > 1) {
			fprintf(stderr, "  [Stack] ");
			for (int i = 0; i < flow->protocol_stack_count; i++) {
				fprintf(stderr, "%s%s", i > 0 ? " -> " : "",
					ndpi_get_proto_name(ctx->ndpi, flow->protocol_stack[i]));
			}
			fprintf(stderr, "\n");
		}

		if (protocol.proto.app_protocol == NDPI_PROTOCOL_TLS && flow->packets_processed <= 10) {
			fprintf(stderr, "  [TLS] dir0=%d dir1=%d sni=%s\n",
				flow->packets_dir0, flow->packets_dir1,
				flow->flow->host_server_name[0] ? flow->flow->host_server_name : "NONE");
		}
	}

	if ((protocol.proto.app_protocol == NDPI_PROTOCOL_DNS ||
	     packet_view.dst_port == 53 || packet_view.src_port == 53) &&
	    packet_view.protocol == IPPROTO_UDP && flow->packets_processed <= 2) {

		const unsigned char *dns_payload = NULL;
		unsigned int dns_len = 0;

		if (packet_view.family == FLOW_FAMILY_IPV4) {
			struct iphdr *iph = (struct iphdr *)ip_packet;
			unsigned int ip_hdr_len = iph->ihl * 4;
			if (ip_hdr_len + 8 < ip_packet_len) {
				dns_payload = ip_packet + ip_hdr_len + 8;
				dns_len = ip_packet_len - ip_hdr_len - 8;
			}
		} else if (packet_view.family == FLOW_FAMILY_IPV6) {
			if (40 + 8 < ip_packet_len) {
				dns_payload = ip_packet + 40 + 8;
				dns_len = ip_packet_len - 40 - 8;
			}
		}

		if (dns_payload && dns_len > 0) {
			char query_name[256];
			struct dns_stats *stats;
			struct flow_addr *client_addr;

			if (packet_view.src_port == 53)
				client_addr = &packet_view.dst;
			else
				client_addr = &packet_view.src;

			stats = dns_lookup(ctx, client_addr, packet_view.family);
			if (!stats)
				stats = dns_insert(ctx, client_addr, packet_view.family);

			if (stats) {
				if (packet_view.dst_port == 53) {
					stats->queries++;
					if (extract_dns_query_name(dns_payload, dns_len, query_name, sizeof(query_name)) == 0) {
						strncpy(stats->last_query, query_name, sizeof(stats->last_query) - 1);
						if (ctx->verbose)
							fprintf(stderr, "  [DNS] Query: %s from %s\n", query_name, src_ip);
					}
				} else {
					stats->responses++;
				}
			}
		}
	}

	if (!flow->detection_finalized &&
	    (protocol.state == NDPI_STATE_CLASSIFIED ||
	     protocol.state == NDPI_STATE_MONITORING)) {
		flow->detection_finalized = 1;
		if (ctx->verbose) {
			fprintf(stderr, "  [PKT %d] Flow finalized via nDPI state=%d\n",
				flow->packets_processed, protocol.state);
		}
	}

	int packets_threshold = ctx->pcap_mode ? 50 : PACKETS_TO_SAMPLE;

	if (!flow->detection_finalized && flow->packets_processed >= packets_threshold) {
		if (ctx->verbose)
			fprintf(stderr, "  [PKT %d] Calling ndpi_detection_giveup() [dir0=%d dir1=%d]...\n",
				flow->packets_processed, flow->packets_dir0, flow->packets_dir1);

		protocol = ndpi_detection_giveup(ctx->ndpi, flow->flow);
		flow->detection_finalized = 1;
		flow->protocol_guessed = (protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN);

		if (ctx->verbose) {
			fprintf(stderr, "  [PKT %d] After giveup (guessed=%d, dir0=%d dir1=%d): master=%u (%s) app=%u (%s)\n",
				flow->packets_processed,
				flow->protocol_guessed, flow->packets_dir0, flow->packets_dir1,
				protocol.proto.master_protocol,
				ndpi_get_proto_name(ctx->ndpi, protocol.proto.master_protocol),
				protocol.proto.app_protocol,
				ndpi_get_proto_name(ctx->ndpi, protocol.proto.app_protocol));
		}
	}

	int should_print = 0;
	int newly_classified = 0;
	if (protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
	    protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {

		if (flow->protocol.proto.master_protocol != protocol.proto.master_protocol ||
		    flow->protocol.proto.app_protocol != protocol.proto.app_protocol) {
			should_print = 1;

			if (flow->protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN &&
			    flow->protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN)
				newly_classified = 1;

			if (ctx->verbose) {
				fprintf(stderr, "  [PKT %d] Classification changed: old master=%u app=%u -> new master=%u app=%u\n",
					flow->packets_processed,
					flow->protocol.proto.master_protocol,
					flow->protocol.proto.app_protocol,
					protocol.proto.master_protocol,
					protocol.proto.app_protocol);
			}
		}

		flow->protocol = protocol;

		if (newly_classified)
			emit_classification_event(ctx, flow, interface_name_by_index(ctx, sample->ifindex));
	}
}

static int handle_sample(void *ctx, void *data, size_t len)
{
	struct classifi_ctx *classifi_ctx = ctx;
	struct packet_sample *sample = data;

	if (len < sizeof(*sample))
		return 0;

	classify_packet(classifi_ctx, sample);
	return 0;
}

static int detach_interface(struct classifi_ctx *ctx, struct interface_info *iface)
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

static void detach_tc_program(struct classifi_ctx *ctx)
{
	while (ctx->num_interfaces > 0)
		detach_interface(ctx, &ctx->interfaces[0]);
}

static int attach_tc_program(struct classifi_ctx *ctx, int prog_fd,
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

	/* safety net: previous instance may not have cleaned up (SIGKILL, crash) */
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

static void print_flow_stats(int flow_map_fd)
{
	struct flow_key key, next_key;
	struct flow_info info;
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	int count = 0;

	printf("\n=== Flow Statistics ===\n");

	memset(&key, 0, sizeof(key));
	while (bpf_map_get_next_key(flow_map_fd, &key, &next_key) == 0) {
			if (bpf_map_lookup_elem(flow_map_fd, &next_key, &info) == 0) {
				flow_key_to_strings(&next_key, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

			printf("Flow: %s:%u -> %s:%u proto=%u packets=%llu bytes=%llu\n",
			       src_ip, next_key.src_port,
			       dst_ip, next_key.dst_port,
			       next_key.protocol,
			       info.packets, info.bytes);
			count++;
		}
		key = next_key;
	}

	printf("Total flows: %d\n\n", count);
}

static void print_dns_summary(struct classifi_ctx *ctx)
{
	char client_ip[INET6_ADDRSTRLEN];
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char timestamp[20];
	int total_clients = 0;

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

	printf("\n=== DNS Summary ===\n");

	for (int i = 0; i < DNS_TABLE_SIZE; i++) {
		struct dns_stats *stats = ctx->dns_table[i];
		while (stats) {
			if (stats->family == FLOW_FAMILY_IPV4) {
				struct in_addr addr = { .s_addr = (__u32)stats->client_ip.lo };
				inet_ntop(AF_INET, &addr, client_ip, sizeof(client_ip));
			} else if (stats->family == FLOW_FAMILY_IPV6) {
				struct in6_addr addr6;
				memcpy(&addr6, &stats->client_ip, sizeof(addr6));
				inet_ntop(AF_INET6, &addr6, client_ip, sizeof(client_ip));
			} else {
				snprintf(client_ip, sizeof(client_ip), "unknown");
			}

			printf("%s | %-39s | Q:%-5llu R:%-5llu | Last: %s\n",
			       timestamp, client_ip,
			       stats->queries, stats->responses,
			       stats->last_query[0] ? stats->last_query : "(none)");

			total_clients++;
			stats = stats->next;
		}
	}

	if (total_clients == 0)
		printf("  No DNS activity\n");

	printf("\n");
}

static void print_classified_flows(struct classifi_ctx *ctx)
{
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	const char *master_name, *app_name;
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char timestamp[20];

	struct flow_key summary_key;

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

	for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
		struct ndpi_flow *flow = ctx->flow_table[i];
		while (flow) {
			if (flow->protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
			    flow->protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {

				if (flow->have_first_packet_key)
					summary_key = flow->first_packet_key;
				else
					summary_key = flow->key;

				flow_key_to_strings(&summary_key, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

				if (flow->protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
					master_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.app_protocol);
				else
					master_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.master_protocol);
				app_name = ndpi_get_proto_name(ctx->ndpi, flow->protocol.proto.app_protocol);

				if (ctx->suppress_noisy) {
					if (flow->protocol.proto.app_protocol == NDPI_PROTOCOL_DNS ||
					    summary_key.protocol == IPPROTO_ICMP ||
					    summary_key.protocol == IPPROTO_ICMPV6 ||
					    summary_key.protocol == 2) {
						flow = flow->next;
						continue;
					}
				}

				const char *category_name = ndpi_category_get_name(ctx->ndpi, flow->protocol.category);

				printf("%s | %-39s:%-5u -> %-39s:%-5u proto=%-3u | %-8s / %-20s | %-16s | pkts=%d (d0:%d d1:%d)\n",
				       timestamp,
				       src_ip, summary_key.src_port,
				       dst_ip, summary_key.dst_port,
				       summary_key.protocol,
				       master_name, app_name,
				       category_name,
				       flow->packets_processed,
				       flow->packets_dir0, flow->packets_dir1);
			}
			flow = flow->next;
		}
	}

	if (ctx->suppress_noisy)
		print_dns_summary(ctx);
}

static void cleanup_expired_flows(struct classifi_ctx *ctx)
{
	time_t now = time(NULL);
	int total_flows = 0;
	int expired_flows = 0;

	for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
		struct ndpi_flow **prev = &ctx->flow_table[i];
		struct ndpi_flow *flow = ctx->flow_table[i];

		while (flow) {
			total_flows++;

			time_t idle_time = now - flow->last_seen;
			time_t age = now - flow->first_seen;

			int should_expire = 0;
			if (idle_time >= FLOW_IDLE_TIMEOUT) {
				should_expire = 1;
				if (ctx->verbose)
					fprintf(stderr, "expiring idle flow (idle %ld sec)\n", idle_time);
			} else if (age >= FLOW_ABSOLUTE_TIMEOUT) {
				should_expire = 1;
				if (ctx->verbose)
					fprintf(stderr, "expiring old flow (age %ld sec)\n", age);
			}

			if (should_expire) {
				struct ndpi_flow *to_free = flow;

				*prev = flow->next;
				flow = flow->next;

				if (ctx->flow_map_fd >= 0)
					bpf_map_delete_elem(ctx->flow_map_fd, &to_free->key);

				if (to_free->flow)
					ndpi_flow_free(to_free->flow);
				free(to_free);

				expired_flows++;
			} else {
				prev = &flow->next;
				flow = flow->next;
			}
		}
	}

	if (ctx->verbose && expired_flows > 0) {
		fprintf(stderr, "flow cleanup: %d active, %d expired\n",
			total_flows - expired_flows, expired_flows);
	}
}

void flow_table_iterate(struct classifi_ctx *ctx, flow_visitor_fn visitor, void *user_data)
{
	for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
		struct ndpi_flow *flow = ctx->flow_table[i];
		while (flow) {
			visitor(ctx, flow, user_data);
			flow = flow->next;
		}
	}
}

void dns_table_iterate(struct classifi_ctx *ctx, dns_visitor_fn visitor, void *user_data)
{
	for (int i = 0; i < DNS_TABLE_SIZE; i++) {
		struct dns_stats *stats = ctx->dns_table[i];
		while (stats) {
			visitor(ctx, stats, user_data);
			stats = stats->next;
		}
	}
}

static void pcap_packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr,
				const unsigned char *packet)
{
	struct classifi_ctx *ctx = (struct classifi_ctx *)user;
	struct flow_key key, packet_view;
	unsigned char *l3_data = NULL;
	unsigned int l3_len = 0;
	__u8 direction;
	struct ndpi_flow *flow;
	ndpi_protocol protocol;
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	struct ndpi_flow_input_info input_info = {0};
	static unsigned long long total_packets = 0;

	total_packets++;

	if (parse_packet_libpcap(packet, pkthdr->caplen, &key, &l3_data, &l3_len, &direction) < 0)
		return;

	direction = canonicalize_flow_key_libpcap(&key);

	if (should_filter_flow(ctx, &key))
		return;

	packet_view = key;
	if (direction)
		swap_flow_endpoints(&packet_view);

	flow_key_to_strings(&packet_view, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

	flow = flow_table_lookup(ctx, &key);
	if (!flow) {
		flow = flow_table_insert(ctx, &key);
		if (!flow) {
			fprintf(stderr, "failed to create flow for %s:%u -> %s:%u\n",
				src_ip, packet_view.src_port,
				dst_ip, packet_view.dst_port);
			return;
		}
		if (ctx->verbose) {
			fprintf(stderr, "new flow: %s:%u -> %s:%u proto=%u\n",
				src_ip, packet_view.src_port,
				dst_ip, packet_view.dst_port, packet_view.protocol);
		}
	}

	if (!flow->have_first_packet_key) {
		flow->first_packet_key = packet_view;
		flow->have_first_packet_key = 1;
	}

	flow->packets_processed++;
	flow->last_seen = time(NULL);
	if (direction == 0)
		flow->packets_dir0++;
	else
		flow->packets_dir1++;

	if (ctx->verbose && (flow->packets_processed <= 50 || flow->packets_processed % 20 == 0)) {
		fprintf(stderr, "packet %llu (flow pkt %d, dir=%u): %s:%u -> %s:%u proto=%u len=%u [dir0=%d dir1=%d]\n",
			total_packets, flow->packets_processed, direction,
			src_ip, packet_view.src_port,
			dst_ip, packet_view.dst_port, packet_view.protocol,
			l3_len, flow->packets_dir0, flow->packets_dir1);
	}

	if (flow->detection_finalized)
		return;

	input_info.in_pkt_dir = direction ? 1 : 0;
	input_info.seen_flow_beginning = (flow->packets_processed == 1);

	if (!l3_data || l3_len == 0) {
		if (ctx->verbose)
			fprintf(stderr, "  no L3 data, skipping nDPI\n");
		return;
	}

	u_int64_t time_ms = pkthdr->ts.tv_sec * 1000ULL + pkthdr->ts.tv_usec / 1000ULL;

	protocol = ndpi_detection_process_packet(
		ctx->ndpi, flow->flow, l3_data, l3_len,
		time_ms, &input_info);

	if (flow->flow->tcp.fingerprint && flow->flow->tcp.fingerprint[0] &&
	    !flow->tcp_fingerprint[0]) {
		snprintf(flow->tcp_fingerprint, sizeof(flow->tcp_fingerprint), "%s",
			 flow->flow->tcp.fingerprint);
		snprintf(flow->os_hint, sizeof(flow->os_hint), "%s",
			 ndpi_print_os_hint(flow->flow->tcp.os_hint));
	}

	if (protocol.protocol_stack.protos_num > 0 && flow->protocol_stack_count == 0) {
		flow->protocol_stack_count = protocol.protocol_stack.protos_num;
		for (int i = 0; i < protocol.protocol_stack.protos_num && i < 8; i++)
			flow->protocol_stack[i] = protocol.protocol_stack.protos[i];
	}

	if (ctx->verbose && (flow->packets_processed <= 50 || flow->packets_processed % 20 == 0)) {
		fprintf(stderr, "  [PKT %d] nDPI process_packet: master=%u (%s) app=%u (%s) category=%s state=%d\n",
			flow->packets_processed,
			protocol.proto.master_protocol,
			ndpi_get_proto_name(ctx->ndpi, protocol.proto.master_protocol),
			protocol.proto.app_protocol,
			ndpi_get_proto_name(ctx->ndpi, protocol.proto.app_protocol),
			ndpi_category_get_name(ctx->ndpi, protocol.category),
			protocol.state);

		if (flow->tcp_fingerprint[0]) {
			fprintf(stderr, "  [TCP FP] %s (OS: %s)\n",
				flow->tcp_fingerprint, flow->os_hint);
		}

		if (flow->protocol_stack_count > 1) {
			fprintf(stderr, "  [Stack] ");
			for (int i = 0; i < flow->protocol_stack_count; i++) {
				fprintf(stderr, "%s%s", i > 0 ? " -> " : "",
					ndpi_get_proto_name(ctx->ndpi, flow->protocol_stack[i]));
			}
			fprintf(stderr, "\n");
		}

		if (protocol.proto.app_protocol == NDPI_PROTOCOL_TLS && flow->packets_processed <= 10) {
			fprintf(stderr, "  [TLS] dir0=%d dir1=%d sni=%s\n",
				flow->packets_dir0, flow->packets_dir1,
				flow->flow->host_server_name[0] ? flow->flow->host_server_name : "NONE");
		}
	}

	if ((protocol.proto.app_protocol == NDPI_PROTOCOL_DNS ||
	     packet_view.dst_port == 53 || packet_view.src_port == 53) &&
	    packet_view.protocol == IPPROTO_UDP && flow->packets_processed <= 2) {

		const unsigned char *dns_payload = NULL;
		unsigned int dns_len = 0;

		if (packet_view.family == FLOW_FAMILY_IPV4) {
			struct iphdr *iph = (struct iphdr *)l3_data;
			unsigned int ip_hdr_len = iph->ihl * 4;
			if (ip_hdr_len + 8 < l3_len) {
				dns_payload = l3_data + ip_hdr_len + 8;
				dns_len = l3_len - ip_hdr_len - 8;
			}
		} else if (packet_view.family == FLOW_FAMILY_IPV6) {
			if (40 + 8 < l3_len) {
				dns_payload = l3_data + 40 + 8;
				dns_len = l3_len - 40 - 8;
			}
		}

		if (dns_payload && dns_len > 0) {
			char query_name[256];
			struct dns_stats *stats;
			struct flow_addr *client_addr;

			if (packet_view.src_port == 53)
				client_addr = &packet_view.dst;
			else
				client_addr = &packet_view.src;

			stats = dns_lookup(ctx, client_addr, packet_view.family);
			if (!stats)
				stats = dns_insert(ctx, client_addr, packet_view.family);

			if (stats) {
				if (packet_view.dst_port == 53) {
					stats->queries++;
					if (extract_dns_query_name(dns_payload, dns_len, query_name, sizeof(query_name)) == 0) {
						strncpy(stats->last_query, query_name, sizeof(stats->last_query) - 1);
						if (ctx->verbose)
							fprintf(stderr, "  [DNS] Query: %s from %s\n", query_name, src_ip);
					}
				} else {
					stats->responses++;
				}
			}
		}
	}

	if (!flow->detection_finalized &&
	    (protocol.state == NDPI_STATE_CLASSIFIED ||
	     protocol.state == NDPI_STATE_MONITORING)) {
		flow->detection_finalized = 1;
		if (ctx->verbose) {
			fprintf(stderr, "  [PKT %d] Flow finalized via nDPI state=%d\n",
				flow->packets_processed, protocol.state);
		}
	}

	if (!flow->detection_finalized && flow->packets_processed >= 50) {
		if (ctx->verbose)
			fprintf(stderr, "  [PKT %d] Calling ndpi_detection_giveup() [dir0=%d dir1=%d]...\n",
				flow->packets_processed, flow->packets_dir0, flow->packets_dir1);

		protocol = ndpi_detection_giveup(ctx->ndpi, flow->flow);
		flow->detection_finalized = 1;
		flow->protocol_guessed = (protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN);

		if (ctx->verbose) {
			fprintf(stderr, "  [PKT %d] After giveup (guessed=%d, dir0=%d dir1=%d): master=%u (%s) app=%u (%s)\n",
				flow->packets_processed,
				flow->protocol_guessed, flow->packets_dir0, flow->packets_dir1,
				protocol.proto.master_protocol,
				ndpi_get_proto_name(ctx->ndpi, protocol.proto.master_protocol),
				protocol.proto.app_protocol,
				ndpi_get_proto_name(ctx->ndpi, protocol.proto.app_protocol));
		}
	}

	int newly_classified = 0;
	if (protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
	    protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {

		if (flow->protocol.proto.master_protocol != protocol.proto.master_protocol ||
		    flow->protocol.proto.app_protocol != protocol.proto.app_protocol) {
			if (flow->protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN &&
			    flow->protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN)
				newly_classified = 1;
		}

		flow->protocol = protocol;

		if (newly_classified && ctx->pcap_ifname)
			emit_classification_event(ctx, flow, ctx->pcap_ifname);
	}
}

static int run_pcap_mode(struct classifi_ctx *ctx, const char *ifname)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	fprintf(stderr, "starting libpcap capture on %s\n", ifname);
	fprintf(stderr, "WARNING: This mode captures ALL packets and is CPU-intensive!\n");

	handle = pcap_open_live(ifname, 65535, 1, 100, errbuf);
	if (!handle) {
		fprintf(stderr, "failed to open interface %s: %s\n", ifname, errbuf);
		return -1;
	}

	ctx->flow_map_fd = -1;

	time_t last_cleanup = time(NULL);
	while (keep_running) {
		int ret = pcap_dispatch(handle, 100, pcap_packet_handler, (unsigned char *)ctx);

		if (ret < 0) {
			fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
			break;
		}

		time_t now = time(NULL);
		if (now - last_cleanup >= CLEANUP_INTERVAL) {
			cleanup_expired_flows(ctx);
			last_cleanup = now;
		}
	}

	pcap_close(handle);
	return 0;
}

static void print_ringbuf_stats(struct classifi_ctx *ctx)
{
	__u32 key = 0;
	__u64 drops = 0;

	if (ctx->ringbuf_stats_fd >= 0 &&
	    bpf_map_lookup_elem(ctx->ringbuf_stats_fd, &key, &drops) == 0) {
		if (drops > ctx->last_ringbuf_drops) {
			__u64 new_drops = drops - ctx->last_ringbuf_drops;
			fprintf(stderr, "WARNING: Ring buffer dropped %llu packet samples (total: %llu)\n",
				new_drops, drops);
			ctx->last_ringbuf_drops = drops;
		}
	}
}

static void ringbuf_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct classifi_ctx *ctx = container_of(fd, struct classifi_ctx, ringbuf_uloop_fd);

	if (!ctx->ringbuf)
		return;

	int err = ring_buffer__consume(ctx->ringbuf);
	if (err < 0 && err != -EAGAIN)
		fprintf(stderr, "error consuming ring buffer: %d\n", err);
}

static void cleanup_timer_cb(struct uloop_timeout *t)
{
	struct classifi_ctx *ctx = container_of(t, struct classifi_ctx, cleanup_timer);
	cleanup_expired_flows(ctx);
	uloop_timeout_set(t, CLEANUP_INTERVAL * 1000);
}

static void stats_timer_cb(struct uloop_timeout *t)
{
	struct classifi_ctx *ctx = container_of(t, struct classifi_ctx, stats_timer);
	print_ringbuf_stats(ctx);
	uloop_timeout_set(t, 10 * 1000);
}

int main(int argc, char **argv)
{
	struct classifi_ctx ctx = {0};
	struct bpf_program *prog;
	int prog_fd, samples_fd;
	int err = 0;
	const char *bpf_obj_path;
	const char *iface_names[MAX_INTERFACES];
	int num_iface_names = 0;
	int discover_mode = 0;
	int opt_idx = 1;

	ctx.suppress_noisy = 1;

	while (opt_idx < argc && argv[opt_idx][0] == '-') {
		if (strcmp(argv[opt_idx], "-v") == 0 ||
		    strcmp(argv[opt_idx], "--verbose") == 0) {
			ctx.verbose = 1;
			opt_idx++;
		} else if (strcmp(argv[opt_idx], "-s") == 0 ||
		           strcmp(argv[opt_idx], "--stats") == 0) {
			ctx.periodic_stats = 1;
			opt_idx++;
		} else if (strcmp(argv[opt_idx], "-p") == 0 ||
		           strcmp(argv[opt_idx], "--pcap") == 0) {
			ctx.pcap_mode = 1;
			opt_idx++;
		} else if (strcmp(argv[opt_idx], "-n") == 0 ||
		           strcmp(argv[opt_idx], "--noisy") == 0) {
			ctx.suppress_noisy = 0;
			opt_idx++;
		} else if (strcmp(argv[opt_idx], "-i") == 0 ||
		           strcmp(argv[opt_idx], "--interface") == 0) {
			if (opt_idx + 1 >= argc) {
				fprintf(stderr, "option %s requires an interface name\n", argv[opt_idx]);
				return 1;
			}
			if (num_iface_names >= MAX_INTERFACES) {
				fprintf(stderr, "too many interfaces (max %d)\n", MAX_INTERFACES);
				return 1;
			}
			iface_names[num_iface_names++] = argv[opt_idx + 1];
			opt_idx += 2;
		} else if (strcmp(argv[opt_idx], "-d") == 0 ||
		           strcmp(argv[opt_idx], "--discover") == 0) {
			num_iface_names = discover_interfaces_from_uci(iface_names, MAX_INTERFACES);
			discover_mode = 1;
			opt_idx++;
		} else {
			fprintf(stderr, "unknown option: %s\n", argv[opt_idx]);
			fprintf(stderr, "usage: %s [-v] [-s] [-n] [-p] [-d] -i <interface> [...] <bpf_object.o>\n", argv[0]);
			return 1;
		}
	}

	if (ctx.pcap_mode) {
		if (num_iface_names != 1) {
			fprintf(stderr, "usage (pcap mode): %s [-v] [-s] [-n] -p -i <interface>\n", argv[0]);
			fprintf(stderr, "PCAP mode requires exactly one interface\n");
			return 1;
		}
		bpf_obj_path = NULL;
	} else {
		if (num_iface_names < 1) {
			fprintf(stderr, "no interfaces specified. Use -i <interface> or -d to discover.\n");
			return 1;
		}
		if (argc - opt_idx < 1) {
			fprintf(stderr, "usage (eBPF mode): %s [-v] [-s] [-n] [-d] -i <interface> [...] <bpf_object.o>\n", argv[0]);
			return 1;
		}
		bpf_obj_path = argv[opt_idx];
	}

	setup_signals();

	uloop_init();
	ctx.ubus_ctx = ubus_connect(NULL);
	if (!ctx.ubus_ctx) {
		fprintf(stderr, "warning: failed to connect to ubus, events will not be emitted\n");
	} else {
		ubus_add_uloop(ctx.ubus_ctx);
		if (classifi_ubus_init(&ctx) != 0)
			fprintf(stderr, "warning: failed to initialize classifi ubus\n");
		if (ctx.verbose)
			fprintf(stderr, "connected to ubus for event emission\n");
	}

	ctx.ndpi = setup_ndpi();
	if (!ctx.ndpi) {
		fprintf(stderr, "failed to initialize nDPI\n");
		return 1;
	}

	if (ctx.pcap_mode) {
		ctx.pcap_ifname = iface_names[0];
		err = run_pcap_mode(&ctx, iface_names[0]);
		goto cleanup;
	}

	ctx.bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (libbpf_get_error(ctx.bpf_obj)) {
		fprintf(stderr, "failed to open BPF object: %s\n", bpf_obj_path);
		ctx.bpf_obj = NULL;
		return 1;
	}

	if (bpf_object__load(ctx.bpf_obj)) {
		fprintf(stderr, "failed to load BPF object\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(ctx.bpf_obj, "classifi");
	if (!prog) {
		fprintf(stderr, "failed to find classifi program\n");
		goto cleanup;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "failed to get program fd\n");
		goto cleanup;
	}

	ctx.flow_map_fd = bpf_object__find_map_fd_by_name(ctx.bpf_obj, "flow_map");
	samples_fd = bpf_object__find_map_fd_by_name(ctx.bpf_obj, "packet_samples");
	ctx.ringbuf_stats_fd = bpf_object__find_map_fd_by_name(ctx.bpf_obj, "ringbuf_stats");

	if (ctx.flow_map_fd < 0 || samples_fd < 0 || ctx.ringbuf_stats_fd < 0) {
		fprintf(stderr, "failed to find BPF maps\n");
		goto cleanup;
	}

	ctx.bpf_prog_fd = prog_fd;

	for (int i = 0; i < num_iface_names; i++) {
		if (attach_tc_program(&ctx, prog_fd, iface_names[i], discover_mode) < 0) {
			fprintf(stderr, "failed to attach program to interface %s\n", iface_names[i]);
			goto cleanup;
		}
		get_interface_ip(&ctx.interfaces[ctx.num_interfaces - 1]);
	}

	ctx.ringbuf = ring_buffer__new(samples_fd, handle_sample, &ctx, NULL);
	if (!ctx.ringbuf) {
		fprintf(stderr, "failed to create ring buffer\n");
		goto cleanup;
	}

	int rb_epoll_fd = ring_buffer__epoll_fd(ctx.ringbuf);
	if (rb_epoll_fd < 0) {
		fprintf(stderr, "failed to get ring buffer epoll fd\n");
		goto cleanup;
	}

	ctx.ringbuf_uloop_fd.fd = rb_epoll_fd;
	ctx.ringbuf_uloop_fd.cb = ringbuf_fd_cb;
	uloop_fd_add(&ctx.ringbuf_uloop_fd, ULOOP_READ);

	ctx.cleanup_timer.cb = cleanup_timer_cb;
	uloop_timeout_set(&ctx.cleanup_timer, CLEANUP_INTERVAL * 1000);

	ctx.stats_timer.cb = stats_timer_cb;
	uloop_timeout_set(&ctx.stats_timer, 10 * 1000);

	__u32 stats_key = 0;
	bpf_map_lookup_elem(ctx.ringbuf_stats_fd, &stats_key, &ctx.last_ringbuf_drops);

	printf("classifi running on %d interface(s):", ctx.num_interfaces);
	for (int i = 0; i < ctx.num_interfaces; i++)
		printf(" %s", ctx.interfaces[i].name);
	printf("\n");

	uloop_run();

	printf("\nshutting down...\n");

cleanup:
	uloop_fd_delete(&ctx.ringbuf_uloop_fd);
	uloop_timeout_cancel(&ctx.cleanup_timer);
	uloop_timeout_cancel(&ctx.stats_timer);
	detach_tc_program(&ctx);
	ring_buffer__free(ctx.ringbuf);
	ctx.ringbuf = NULL;
	bpf_object__close(ctx.bpf_obj);
	cleanup_flow_table(&ctx);
	cleanup_dns_table(&ctx);
	if (ctx.ndpi)
		ndpi_exit_detection_module(ctx.ndpi);

	if (ctx.ubus_ctx) {
		ubus_free(ctx.ubus_ctx);
		ctx.ubus_ctx = NULL;
	}
	uloop_done();

	return err != 0;
}
