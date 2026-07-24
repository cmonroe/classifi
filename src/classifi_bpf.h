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
#ifndef CLASSIFI_BPF_H
#define CLASSIFI_BPF_H

#include <linux/types.h>

#ifdef __BPF__
#include <linux/in.h>
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif
#ifndef IPPROTO_HIP
#define IPPROTO_HIP 139
#endif
#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6 140
#endif

#define MAX_FLOWS 8192
#define MAX_INTERFACES 8

/*
 * GRO can coalesce multiple TCP segments into a single skb, producing
 * packets larger than MTU. TLS ClientHello with many extensions or
 * certificate data can span multiple segments. 8192 bytes captures
 * these coalesced packets for proper nDPI reassembly and classification.
 */
#define MAX_PACKET_SAMPLE 8192
#define PACKETS_TO_SAMPLE 50

#define FLOW_FAMILY_IPV4 4
#define FLOW_FAMILY_IPV6 6

struct flow_addr {
	__u64 hi;
	__u64 lo;
} __attribute__((packed));

#define FLOW_STATE_NEW       0
#define FLOW_STATE_SAMPLED   1
#define FLOW_STATE_CLASSIFIED 2

struct flow_key {
	__u8 family;
	__u8 protocol;
	__u16 pad0;
	__u16 src_port;
	__u16 dst_port;
	struct flow_addr src;
	struct flow_addr dst;
} __attribute__((packed));

struct iface_stat {
	__u64 packets;
	__u64 bytes;
};

struct flow_info {
	__u64 packets;
	__u64 bytes;
	__u64 first_seen;
	__u64 last_seen;
	/* Interface that created the flow. Traffic routed between two monitored
	 * interfaces hits the hook once per interface; only the owner tracks it,
	 * otherwise every packet is double counted, duplicate samples reach nDPI
	 * and same-ISN duplicate SYNs read as retransmits, which suppresses the
	 * handshake RTT metrics. */
	__u32 ifindex;
	__u8 state;
	__u8 pad[3];
};

struct packet_sample {
	struct flow_key key;
	__u64 ts_ns;
	__u32 data_len;
	__u32 orig_len;         /* on-wire length before the sample clamp */
	__u32 ifindex;
	__u32 tcp_seq;          /* host order; 0 for non-TCP */
	__u32 tcp_ack_seq;      /* host order; 0 for non-TCP */
	__u16 l3_offset;
	__u16 tcp_payload_len;  /* L4 payload bytes; 0 for pure ACK / non-TCP */
	/* GRO aggregation geometry from skb_shared_info: gso_segs original
	 * packets of gso_size L4 payload bytes each (last may be shorter).
	 * Userspace needs both to split a fraglist-GRO'd UDP datagram back
	 * into the wire datagrams before nDPI sees it; QUIC places semantic
	 * boundaries at datagrams, unlike TCP's byte stream. */
	__u16 gso_size;
	__u16 gso_segs;
	__u8 direction;
	/* Raw on-wire TCP flags octet (TCP header byte 13: FIN/SYN/RST/PSH/
	 * ACK/URG/ECE/CWR); 0 for non-TCP. Lifted here, with seq/ack/payload_len
	 * above, so userspace tracks the handshake without re-parsing the bytes. */
	__u8 tcp_flags;
	__u8 data[MAX_PACKET_SAMPLE];
} __attribute__((packed));

#ifdef __BPF__
#define FLOW_INLINE static __always_inline
#define FLOW_UNROLL _Pragma("unroll")
#else
#define FLOW_INLINE static inline
#define FLOW_UNROLL
#endif

FLOW_INLINE void swap_flow_endpoints(struct flow_key *key)
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

FLOW_INLINE __u8 canonicalize_flow_key(struct flow_key *key)
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

/* RFC 8200 4.1 recommends at most 6 extension headers before the upper
 * layer (HBH, DSTOPT, RT, FRAG, AH, DSTOPT); deeper chains give up */
#define IPV6_EH_MAX 6
#define IPV6_EH_SHORT -2

struct ipv6_eh {
	__u16 len;
	__u8 protocol;
	__u8 l4_ok;
	__u8 frag;
	__u8 frag_more;
};

FLOW_INLINE int ipv6_eh_skippable(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_AH:
	case IPPROTO_DSTOPTS:
	case IPPROTO_MH:
	case IPPROTO_HIP:
	case IPPROTO_SHIM6:
		return 1;
	}
	return 0;
}

FLOW_INLINE void ipv6_eh_finish(struct ipv6_eh *out, __u8 nexthdr, __u32 len,
				__u32 payload_limit)
{
	__u32 l4_min = 0;

	if (nexthdr == IPPROTO_TCP)
		l4_min = 20;
	else if (nexthdr == IPPROTO_UDP)
		l4_min = 8;

	out->protocol = nexthdr;
	out->len = len;
	/* ESP hides the transport header behind the SA; NONE has none. The
	 * payload_limit test rejects L4 headers that would extend past the
	 * IP payload into Ethernet min-frame padding the capture includes. */
	out->l4_ok = nexthdr != IPPROTO_ESP && nexthdr != IPPROTO_NONE &&
		     len + l4_min <= payload_limit;
}

/*
 * Walk the IPv6 extension-header chain to the upper-layer protocol.
 * eh points at the byte after the fixed 40-byte header; payload_limit is
 * ntohs(payload_len) and bounds the walk logically even when the capture
 * (data_end) extends further. Returns 0 with *out filled, or
 * IPV6_EH_SHORT when the chain runs past data_end (a larger capture
 * could complete it; *out is still filled with the progress made).
 */
FLOW_INLINE int ipv6_eh_walk(const __u8 *eh, const void *data_end,
			     __u32 payload_limit, __u8 nexthdr,
			     struct ipv6_eh *out)
{
	__u32 len = 0;
	__u32 ext_len;
	int i;

	out->frag = 0;
	out->frag_more = 0;

	FLOW_UNROLL
	for (i = 0; i < IPV6_EH_MAX; i++) {
		if (!ipv6_eh_skippable(nexthdr)) {
			ipv6_eh_finish(out, nexthdr, len, payload_limit);
			return 0;
		}

		/* every EH is at least 8 bytes on the wire, so one uniform
		 * check covers the nexthdr/len and fragment-field reads */
		if ((const void *)(eh + 8) > data_end) {
			out->protocol = nexthdr;
			out->len = len;
			out->l4_ok = 0;
			return IPV6_EH_SHORT;
		}

		if (len + 8 > payload_limit)
			goto giveup;

		if (nexthdr == IPPROTO_FRAGMENT) {
			out->frag = 1;
			/* RFC 8200 4.5: Next Header names the first header of
			 * the fragmentable part in every fragment, but only
			 * the first fragment (offset 0) carries those bytes */
			if ((((__u32)eh[2] << 8) | eh[3]) & 0xFFF8) {
				out->protocol = eh[0];
				out->len = len + 8;
				out->l4_ok = 0;
				return 0;
			}
			out->frag_more = eh[3] & 0x01;
			ext_len = 8;
		} else if (nexthdr == IPPROTO_AH) {
			/* RFC 4302 2.2: AH length is in 4-byte units */
			ext_len = ((__u32)eh[1] + 2) * 4;
		} else {
			ext_len = ((__u32)eh[1] + 1) * 8;
		}

		if (len + ext_len > payload_limit)
			goto giveup;

		nexthdr = eh[0];
		eh += ext_len;
		len += ext_len;
	}

	if (!ipv6_eh_skippable(nexthdr)) {
		ipv6_eh_finish(out, nexthdr, len, payload_limit);
		return 0;
	}

giveup:
	out->protocol = nexthdr;
	out->len = len;
	out->l4_ok = 0;
	return 0;
}

#endif /* CLASSIFI_BPF_H */
