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
#include <string.h>
#include <arpa/inet.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <ndpi/ndpi_api.h>

#include "classifi.h"
#include "classifi_pcap.h"

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define CLEANUP_INTERVAL 30

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
		if (key->src.hi > key->dst.hi)
			swapped = 1;
		else if (key->src.hi == key->dst.hi && key->src.lo > key->dst.lo)
			swapped = 1;
	}

	if (swapped)
		swap_flow_endpoints(key);

	return swapped;
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
	static unsigned long long total_packets = 0;

	total_packets++;

	if (parse_packet_libpcap(packet, pkthdr->caplen, &key, &l3_data, &l3_len, &direction) < 0)
		return;

	direction = canonicalize_flow_key_libpcap(&key);

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
	flow->last_seen = monotonic_time_sec();
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

	if (!l3_data || l3_len == 0) {
		if (ctx->verbose)
			fprintf(stderr, "  no L3 data, skipping nDPI\n");
		return;
	}

	u_int64_t time_ms = pkthdr->ts.tv_sec * 1000ULL + pkthdr->ts.tv_usec / 1000ULL;

	flow->input_info.in_pkt_dir = NDPI_IN_PKT_DIR_UNKNOWN;

	protocol = ndpi_detection_process_packet(
		ctx->ndpi, flow->flow, l3_data, l3_len,
		time_ms, &flow->input_info);

	if (flow->flow->tcp.fingerprint && flow->flow->tcp.fingerprint[0] &&
	    !flow->tcp_fingerprint[0]) {
		snprintf(flow->tcp_fingerprint, sizeof(flow->tcp_fingerprint), "%s",
			 flow->flow->tcp.fingerprint);
		snprintf(flow->os_hint, sizeof(flow->os_hint), "%s",
			 ndpi_print_os_hint(flow->flow->tcp.os_hint));
	}

	if (protocol.protocol_stack.protos_num > 0 && flow->protocol_stack_count == 0) {
		int stack_count = protocol.protocol_stack.protos_num;
		if (stack_count > 8)
			stack_count = 8;
		flow->protocol_stack_count = stack_count;
		for (int i = 0; i < stack_count; i++)
			flow->protocol_stack[i] = protocol.protocol_stack.protos[i];
	}

	flow->multimedia_types = flow->flow->flow_multimedia_types;

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

		if (flow->multimedia_types) {
			char stream_content[64];
			if (ndpi_multimedia_flowtype2str(stream_content, sizeof(stream_content),
							 flow->multimedia_types))
				fprintf(stderr, "  [Stream] %s\n", stream_content);
		}

		if (protocol.proto.app_protocol == NDPI_PROTOCOL_TLS && flow->packets_processed <= 10) {
			fprintf(stderr, "  [TLS] %s -> %s dir0=%d dir1=%d ch=%d sh=%d sni=%s\n",
				src_ip, dst_ip,
				flow->packets_dir0, flow->packets_dir1,
				flow->flow->protos.tls_quic.client_hello_processed,
				flow->flow->protos.tls_quic.server_hello_processed,
				flow->flow->host_server_name[0] ? flow->flow->host_server_name : "NONE");
		}
	}

	if ((protocol.proto.app_protocol == NDPI_PROTOCOL_DNS ||
	     packet_view.dst_port == 53) &&
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
			uint16_t qtype = 0;

			if (extract_dns_query_name(dns_payload, dns_len, query_name, sizeof(query_name), &qtype) == 0) {
				emit_dns_event(ctx, src_ip, query_name, qtype, ctx->pcap_ifname);
				if (ctx->verbose)
					fprintf(stderr, "  [DNS] Query: %s from %s\n", query_name, src_ip);
			}
		}
	}

	if (!flow->detection_finalized &&
	    (protocol.state == NDPI_STATE_CLASSIFIED ||
	     protocol.state == NDPI_STATE_MONITORING) &&
	    flow->flow->extra_packets_func == NULL) {
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

		if (newly_classified && ctx->pcap_ifname) {
			if (tls_quic_metadata_ready(flow)) {
				emit_classification_event(ctx, flow, ctx->pcap_ifname);
			} else {
				flow->classification_event_pending = 1;
				if (ctx->verbose)
					fprintf(stderr, "  [PKT %d] Deferring event for TLS/QUIC metadata\n",
						flow->packets_processed);
			}
		} else if (flow->classification_event_pending && ctx->pcap_ifname &&
			   tls_quic_metadata_ready(flow)) {
			emit_classification_event(ctx, flow, ctx->pcap_ifname);
			flow->classification_event_pending = 0;
			if (ctx->verbose)
				fprintf(stderr, "  [PKT %d] Emitting deferred TLS/QUIC event (SNI=%s)\n",
					flow->packets_processed,
					flow->flow->host_server_name[0] ? flow->flow->host_server_name : "none");
		}
	}
}

int run_pcap_mode(struct classifi_ctx *ctx, const char *ifname)
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

	uint64_t last_cleanup = monotonic_time_sec();
	while (keep_running) {
		int ret = pcap_dispatch(handle, 100, pcap_packet_handler, (unsigned char *)ctx);

		if (ret < 0) {
			fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
			break;
		}

		uint64_t now = monotonic_time_sec();
		if (now - last_cleanup >= CLEANUP_INTERVAL) {
			cleanup_expired_flows(ctx);
			last_cleanup = now;
		}
	}

	pcap_close(handle);
	return 0;
}
