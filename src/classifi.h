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
#ifndef CLASSIFI_H
#define CLASSIFI_H

#include <stdint.h>
#include <time.h>
#include <regex.h>
#include <ndpi/ndpi_api.h>
#include <bpf/libbpf.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "classifi_bpf.h"

#define MAX_RULES 32
#define MAX_PATTERN_LEN 256
#define MAX_EXTRACTS 4

struct classifi_rule {
	char name[64];
	int enabled;

	struct flow_addr dst_ip;
	__u8 dst_family;
	__u16 dst_port;
	__u8 protocol;
	int has_dst_ip;

	char host_header[128];

	char pattern[MAX_PATTERN_LEN];
	regex_t regex;
	int regex_compiled;

	char script[128];

	uint64_t hits;

	struct classifi_rule *next;
};

static inline uint64_t monotonic_time_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec;
}

#define FLOW_TABLE_SIZE 1024
#define MAX_INTERFACES 8

struct interface_info {
	const char *name;
	int ifindex;
	struct flow_addr local_ip;
	__u8 local_ip_family;
	__u32 local_subnet_mask;
	__u8 discovered;
	__u32 tc_handle_ingress;
	__u32 tc_priority_ingress;
	__u32 tc_handle_egress;
	__u32 tc_priority_egress;
};

struct ndpi_flow {
	struct flow_key key;
	struct flow_key first_packet_key;
	struct ndpi_flow_struct *flow;
	ndpi_protocol protocol;
	int packets_processed;
	int packets_dir0;
	int packets_dir1;
	int detection_finalized;
	int protocol_guessed;
	int have_first_packet_key;
	int classification_event_pending;
	uint64_t first_seen;
	uint64_t last_seen;
	char tcp_fingerprint[64];
	char os_hint[32];
	int protocol_stack_count;
	u_int16_t protocol_stack[8];
	__u32 rules_matched;

	ndpi_risk risk;
	u_int16_t risk_score;
	u_int16_t risk_score_client;
	u_int16_t risk_score_server;

	u_int8_t multimedia_types;

	struct ndpi_flow_input_info input_info;

	struct ndpi_flow *next;
};

struct classifi_ctx {
	struct ndpi_detection_module_struct *ndpi;

	struct ndpi_flow *flow_table[FLOW_TABLE_SIZE];

	struct interface_info interfaces[MAX_INTERFACES];
	int num_interfaces;

	struct classifi_rule *rules;
	int num_rules;

	struct bpf_object *bpf_obj;
	int bpf_prog_fd;
	int flow_map_fd;
	int ringbuf_stats_fd;
	struct ring_buffer *ringbuf;

	struct uloop_fd ringbuf_uloop_fd;
	struct uloop_timeout cleanup_timer;
	struct uloop_timeout stats_timer;

	struct ubus_context *ubus_ctx;

	int verbose;
	int periodic_stats;
	int pcap_mode;

	const char *pcap_ifname;

	__u64 last_ringbuf_drops;
};

typedef void (*flow_visitor_fn)(struct classifi_ctx *ctx,
				struct ndpi_flow *flow,
				void *user_data);

void flow_table_iterate(struct classifi_ctx *ctx,
			flow_visitor_fn visitor,
			void *user_data);

#endif /* CLASSIFI_H */
