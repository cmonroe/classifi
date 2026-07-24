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
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define __BPF__
#include "classifi_bpf.h"

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

struct bpf_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

char LICENSE[] SEC("license") = "GPL v2";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_FLOWS);
	__type(key, struct flow_key);
	__type(value, struct flow_info);
} flow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} packet_samples SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_stats SEC(".maps");

/*
 * Staging area for variable-size ring buffer records.
 * bpf_ringbuf_reserve() only takes a compile-time constant size, so
 * reserving in the ring directly costs the full 8KB+ per sample no matter
 * how small the packet is, cutting the 1MB ring to ~120 in-flight samples.
 * Building the record here and emitting it with bpf_ringbuf_output() costs
 * one extra bounded copy but lets a typical packet mix fit an order of
 * magnitude more samples before anything is dropped.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct packet_sample);
} sample_scratch SEC(".maps");

/* L4 metadata parse_flow_key() lifts out of the (already bounds-checked) L4
 * header so the sample carries it directly and userspace need not re-parse. */
struct l4_meta {
	__u32 tcp_seq;          /* host order; 0 for non-TCP */
	__u32 tcp_ack_seq;      /* host order; 0 for non-TCP */
	__u16 tcp_payload_len;  /* L4 payload bytes; 0 for pure ACK / non-TCP */
	__u8 tcp_flags;         /* TCP header byte 13; 0 for non-TCP */
};

#define PARSE_ERR         -1    /* not a packet we track */
#define PARSE_SHORT       -2    /* headers beyond linear data; pull and retry */
#define PARSE_SHORT_KEYED -3    /* short, but the key is complete except for
                                 * ports; usable if a pull cannot finish */

static __always_inline int parse_flow_key(struct __sk_buff *skb,
                                          struct flow_key *key,
                                          __u16 *l3_offset,
                                          struct l4_meta *l4)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u32 offset = sizeof(*eth);
	__be16 h_proto;
	int i;

	if (data + offset > data_end)
		return PARSE_SHORT;

	h_proto = eth->h_proto;

	#pragma unroll
	for (i = 0; i < 2; i++) {
		if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
			struct bpf_vlan_hdr *vh = data + offset;

			if ((void *)vh + sizeof(*vh) > data_end)
				return PARSE_SHORT;

			h_proto = vh->h_vlan_encapsulated_proto;
			offset += sizeof(*vh);
		}
	}

	if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + offset;
		__u32 ip_hdr_len;

		if ((void *)iph + sizeof(*iph) > data_end)
			return PARSE_SHORT;

		ip_hdr_len = iph->ihl * 4;
		if (ip_hdr_len < sizeof(*iph))
			return PARSE_ERR;
		if ((void *)iph + ip_hdr_len > data_end)
			return PARSE_SHORT;

		key->family = FLOW_FAMILY_IPV4;
		key->protocol = iph->protocol;
		key->src_port = 0;
		key->dst_port = 0;
		key->src.hi = 0;
		key->src.lo = (__u64)iph->saddr;
		key->dst.hi = 0;
		key->dst.lo = (__u64)iph->daddr;

		*l3_offset = offset;
		offset += ip_hdr_len;

		/* Non-first fragments carry no L4 header; leave ports zero */
		if (iph->frag_off & bpf_htons(IP_OFFSET))
			return 0;

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph = data + offset;
			__u32 tcp_hdr_len;
			int payload;

			if ((void *)tcph + sizeof(*tcph) > data_end)
				return PARSE_SHORT;

			key->src_port = bpf_ntohs(tcph->source);
			key->dst_port = bpf_ntohs(tcph->dest);
			/* seq/ack/flags/payload-len all live in the just-validated header. */
			l4->tcp_flags = ((const __u8 *)tcph)[13];
			l4->tcp_seq = bpf_ntohl(tcph->seq);
			l4->tcp_ack_seq = bpf_ntohl(tcph->ack_seq);
			tcp_hdr_len = tcph->doff * 4;
			if (tcp_hdr_len < sizeof(*tcph))
				return PARSE_ERR;
			payload = (int)bpf_ntohs(iph->tot_len) - (int)ip_hdr_len - (int)tcp_hdr_len;
			l4->tcp_payload_len = payload < 0 ? 0 :
					      (payload > 0xFFFF ? 0xFFFF : payload);
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph = data + offset;

			if ((void *)udph + sizeof(*udph) > data_end)
				return PARSE_SHORT;

			key->src_port = bpf_ntohs(udph->source);
			key->dst_port = bpf_ntohs(udph->dest);
		}

		return 0;
	}

	if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + offset;
		struct ipv6_eh eh;
		int chain_short;

		if ((void *)ip6h + sizeof(*ip6h) > data_end)
			return PARSE_SHORT;

		key->family = FLOW_FAMILY_IPV6;
		key->src_port = 0;
		key->dst_port = 0;
		__builtin_memcpy(&key->src, &ip6h->saddr, sizeof(struct in6_addr));
		__builtin_memcpy(&key->dst, &ip6h->daddr, sizeof(struct in6_addr));

		*l3_offset = offset;

		chain_short = ipv6_eh_walk((const __u8 *)(ip6h + 1), data_end,
					   bpf_ntohs(ip6h->payload_len),
					   ip6h->nexthdr, &eh);
		/* the walk names the protocol even when the chain outruns
		 * data_end, so the ports-zero key stays usable */
		key->protocol = eh.protocol;
		if (chain_short)
			return PARSE_SHORT_KEYED;

		if (!eh.l4_ok)
			return 0;

		/* mask keeps the verifier's offset bound if eh.len loses its
		 * range through a stack spill; true max is 6 * 2048 = 12288 */
		offset += sizeof(*ip6h) + (eh.len & 0x3FFF);

		if (eh.protocol == IPPROTO_TCP) {
			struct tcphdr *tcph = data + offset;
			__u32 tcp_hdr_len;
			int payload;

			if ((void *)tcph + sizeof(*tcph) > data_end)
				return PARSE_SHORT_KEYED;

			key->src_port = bpf_ntohs(tcph->source);
			key->dst_port = bpf_ntohs(tcph->dest);
			/* seq/ack/flags/payload-len all live in the just-validated header. */
			l4->tcp_flags = ((const __u8 *)tcph)[13];
			l4->tcp_seq = bpf_ntohl(tcph->seq);
			l4->tcp_ack_seq = bpf_ntohl(tcph->ack_seq);
			tcp_hdr_len = tcph->doff * 4;
			if (tcp_hdr_len < sizeof(*tcph))
				return PARSE_ERR;
			payload = (int)bpf_ntohs(ip6h->payload_len) -
				  (int)eh.len - (int)tcp_hdr_len;
			l4->tcp_payload_len = payload < 0 ? 0 :
					      (payload > 0xFFFF ? 0xFFFF : payload);
			/* a first fragment ending right after the TCP header
			 * carries its payload in later fragments (M=1), so it
			 * must not read as a pure ACK to handshake tracking */
			if (eh.frag_more && l4->tcp_payload_len == 0)
				l4->tcp_payload_len = 1;
		} else if (eh.protocol == IPPROTO_UDP) {
			struct udphdr *udph = data + offset;

			if ((void *)udph + sizeof(*udph) > data_end)
				return PARSE_SHORT_KEYED;

			key->src_port = bpf_ntohs(udph->source);
			key->dst_port = bpf_ntohs(udph->dest);
		}

		return 0;
	}

	return PARSE_ERR;
}

static __always_inline void sample_drop_count(void)
{
	__u32 stats_key = 0;
	__u64 *count = bpf_map_lookup_elem(&ringbuf_stats, &stats_key);

	if (count)
		__sync_fetch_and_add(count, 1);
}

static __always_inline void sample_packet(struct __sk_buff *skb,
                                          struct flow_key *key,
                                          __u8 direction,
                                          __u64 ts_ns,
                                          __u16 l3_offset,
                                          const struct l4_meta *l4)
{
	struct packet_sample *sample;
	__u32 scratch_key = 0;
	__u32 len, size;

	sample = bpf_map_lookup_elem(&sample_scratch, &scratch_key);
	if (!sample)
		return;

	len = skb->len;
	if (len > MAX_PACKET_SAMPLE)
		len = MAX_PACKET_SAMPLE;

	if (len == 0 || bpf_skb_load_bytes(skb, 0, sample->data, len) < 0) {
		sample_drop_count();
		return;
	}

	__builtin_memcpy(&sample->key, key, sizeof(*key));
	sample->ts_ns = ts_ns;
	sample->orig_len = skb->len;
	sample->ifindex = skb->ifindex;
	sample->l3_offset = l3_offset;
	sample->direction = direction;
	sample->tcp_flags = l4->tcp_flags;
	sample->tcp_seq = l4->tcp_seq;
	sample->tcp_ack_seq = l4->tcp_ack_seq;
	sample->tcp_payload_len = l4->tcp_payload_len;
	sample->gso_size = skb->gso_size;
	sample->gso_segs = skb->gso_segs;
	sample->data_len = len;

	size = offsetof(struct packet_sample, data) + len;
	if (size > sizeof(*sample))
		return;

	if (bpf_ringbuf_output(&packet_samples, sample, size, 0) < 0)
		sample_drop_count();
}

SEC("tc")
int classifi(struct __sk_buff *skb)
{
	struct flow_key key = {};
	struct flow_info *info, new_info = {};
	__u64 now = bpf_ktime_get_ns();
	__u8 direction;
	__u64 old_count;
	__u16 l3_offset = 0;
	struct l4_meta l4 = {};
	int ret;

	/*
	 * Forwarded traffic normally has the headers in the linear area, so
	 * parse directly and pull only on demand: bpf_skb_pull_data() forces
	 * the skb writable, which unclones every cloned skb it touches.
	 * Headers only; larger pulls collapse FRAGLIST-GRO chains downstream.
	 * 256 covers the full header stack incl. realistic IPv6 extension
	 * chains (eth 14 + 2 VLANs 8 + IPv6 40 + ~100 EH + TCP 60); 128 was
	 * already marginal with zero EHs.
	 * Clamp to skb->len: bpf_skb_pull_data() fails when asked for more
	 * bytes than the packet holds, which would drop every short packet
	 * (TCP SYN/SYN-ACK/ACK, small DNS queries) before it can be
	 * tracked/sampled.
	 */
	ret = parse_flow_key(skb, &key, &l3_offset, &l4);
	if (ret == PARSE_SHORT || ret == PARSE_SHORT_KEYED) {
		__u32 pull_len = skb->len < 256 ? skb->len : 256;

		if (bpf_skb_pull_data(skb, pull_len) < 0)
			return TC_ACT_OK;

		ret = parse_flow_key(skb, &key, &l3_offset, &l4);
	}
	/* a keyed parse that is still short after the pull (an IPv6
	 * extension chain outrunning it) cannot be completed by pulling
	 * more; track the flow with ports zero instead of losing it */
	if (ret == PARSE_SHORT_KEYED)
		ret = 0;
	if (ret < 0)
		return TC_ACT_OK;

	direction = canonicalize_flow_key(&key);

	info = bpf_map_lookup_elem(&flow_map, &key);
	if (!info) {
		new_info.packets = 1;
		new_info.bytes = skb->len;
		new_info.first_seen = now;
		new_info.last_seen = now;
		new_info.ifindex = skb->ifindex;
		new_info.state = FLOW_STATE_NEW;

		if (bpf_map_update_elem(&flow_map, &key, &new_info, BPF_ANY) < 0) {
			sample_drop_count();
			return TC_ACT_OK;
		}
		sample_packet(skb, &key, direction, now, l3_offset, &l4);

		return TC_ACT_OK;
	}

	if (info->ifindex != skb->ifindex)
		return TC_ACT_OK;

	/* Refresh idle tracking without dirtying the cacheline per packet;
	 * userspace expiry works on FLOW_IDLE_TIMEOUT granularity. */
	if (now - info->last_seen > 1000000000ULL)
		info->last_seen = now;

	if (info->state != FLOW_STATE_NEW)
		return TC_ACT_OK;

	old_count = __sync_fetch_and_add(&info->packets, 1);
	__sync_fetch_and_add(&info->bytes, skb->len);

	if (old_count < PACKETS_TO_SAMPLE) {
		sample_packet(skb, &key, direction, now, l3_offset, &l4);

		if (old_count + 1 >= PACKETS_TO_SAMPLE)
			info->state = FLOW_STATE_SAMPLED;
	}

	return TC_ACT_OK;
}
