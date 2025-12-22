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
#include <libubus.h>

#include "classifi_common.h"

#define TICK_RESOLUTION 1000
#define FLOW_TABLE_SIZE 1024

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

static volatile int keep_running = 1;
static int verbose = 0;
static int periodic_stats = 0;
static int pcap_mode = 0;
static int suppress_noisy = 1;
static struct ndpi_detection_module_struct *ndpi = NULL;
static const char *attached_ifname = NULL;
static int attached_ifindex = 0;

static struct ubus_context *ubus_ctx = NULL;

#define FLOW_IDLE_TIMEOUT 30
#define FLOW_ABSOLUTE_TIMEOUT 60
#define CLEANUP_INTERVAL 30

static struct flow_addr local_ip;
static __u8 local_ip_family = 0;
static __u32 local_subnet_mask = 0;

#define HOSTNAME_CACHE_SIZE 256
#define HOSTNAME_CACHE_TTL 300

struct hostname_entry {
	struct flow_addr ip;
	__u8 family;
	char hostname[256];
	time_t last_lookup;
	struct hostname_entry *next;
};

static struct hostname_entry *hostname_cache[HOSTNAME_CACHE_SIZE];

#define DNS_TABLE_SIZE 256
struct dns_stats {
	struct flow_addr client_ip;
	__u8 family;
	__u64 queries;
	__u64 responses;
	char last_query[256];
	struct dns_stats *next;
};

static struct dns_stats *dns_table[DNS_TABLE_SIZE];

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
	time_t first_seen;
	time_t last_seen;
	char tcp_fingerprint[64];
	char os_hint[32];
	int protocol_stack_count;
	u_int16_t protocol_stack[8];
	struct ndpi_flow *next;
};

static struct ndpi_flow *flow_table[FLOW_TABLE_SIZE];

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

static struct dns_stats *dns_lookup(struct flow_addr *addr, __u8 family)
{
	unsigned int hash = dns_hash(addr, family);
	struct dns_stats *stats = dns_table[hash];

	while (stats) {
		if (stats->family == family &&
		    stats->client_ip.hi == addr->hi &&
		    stats->client_ip.lo == addr->lo)
			return stats;
		stats = stats->next;
	}
	return NULL;
}

static struct dns_stats *dns_insert(struct flow_addr *addr, __u8 family)
{
	unsigned int hash = dns_hash(addr, family);
	struct dns_stats *stats = calloc(1, sizeof(*stats));

	if (!stats)
		return NULL;

	stats->family = family;
	stats->client_ip = *addr;
	stats->next = dns_table[hash];
	dns_table[hash] = stats;

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

static struct ndpi_flow *flow_table_lookup(struct flow_key *key)
{
	unsigned int hash = flow_hash(key);
	struct ndpi_flow *flow = flow_table[hash];

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

static int is_local_subnet(struct flow_addr *addr, __u8 family)
{
	if (family == FLOW_FAMILY_IPV4 && local_ip_family == FLOW_FAMILY_IPV4) {
		__u32 ip = (__u32)addr->lo;
		__u32 local = (__u32)local_ip.lo;
		return ((ip & local_subnet_mask) == (local & local_subnet_mask));
	}

	if (family == FLOW_FAMILY_IPV6) {
		if ((addr->hi >> 54) == 0x3FA)
			return 1;
		if (local_ip_family == FLOW_FAMILY_IPV6 && addr->hi == local_ip.hi)
			return 1;
	}

	return 0;
}

static unsigned int hostname_hash(struct flow_addr *addr, __u8 family)
{
	unsigned int hash = FNV_OFFSET;
	hash ^= family;
	hash *= FNV_PRIME;
	hash = fnv_mix64(hash, addr->hi);
	hash = fnv_mix64(hash, addr->lo);
	return hash % HOSTNAME_CACHE_SIZE;
}

static struct hostname_entry *hostname_cache_lookup(struct flow_addr *addr, __u8 family)
{
	unsigned int hash = hostname_hash(addr, family);
	struct hostname_entry *entry = hostname_cache[hash];
	time_t now = time(NULL);

	while (entry) {
		if (entry->family == family &&
		    entry->ip.hi == addr->hi &&
		    entry->ip.lo == addr->lo) {
			if (now - entry->last_lookup < HOSTNAME_CACHE_TTL)
				return entry;
			return NULL;
		}
		entry = entry->next;
	}
	return NULL;
}

static void hostname_cache_insert(struct flow_addr *addr, __u8 family, const char *hostname)
{
	unsigned int hash = hostname_hash(addr, family);
	struct hostname_entry *entry;

	entry = hostname_cache[hash];
	while (entry) {
		if (entry->family == family &&
		    entry->ip.hi == addr->hi &&
		    entry->ip.lo == addr->lo) {
			strncpy(entry->hostname, hostname, sizeof(entry->hostname) - 1);
			entry->hostname[sizeof(entry->hostname) - 1] = '\0';
			entry->last_lookup = time(NULL);
			return;
		}
		entry = entry->next;
	}

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return;

	entry->family = family;
	entry->ip = *addr;
	strncpy(entry->hostname, hostname, sizeof(entry->hostname) - 1);
	entry->hostname[sizeof(entry->hostname) - 1] = '\0';
	entry->last_lookup = time(NULL);

	entry->next = hostname_cache[hash];
	hostname_cache[hash] = entry;
}

static const char *resolve_hostname(struct flow_addr *addr, __u8 family, char *fallback_ip)
{
	struct hostname_entry *cached;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char hostname[256];
	int ret;

	if (!is_local_subnet(addr, family))
		return fallback_ip;

	cached = hostname_cache_lookup(addr, family);
	if (cached)
		return cached->hostname;

	memset(&ss, 0, sizeof(ss));

	if (family == FLOW_FAMILY_IPV4) {
		sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = (__u32)addr->lo;
		ret = getnameinfo((struct sockaddr *)&ss, sizeof(*sin),
				  hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD);
	} else if (family == FLOW_FAMILY_IPV6) {
		sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, addr, sizeof(struct in6_addr));
		ret = getnameinfo((struct sockaddr *)&ss, sizeof(*sin6),
				  hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD);
	} else {
		return fallback_ip;
	}

	if (ret == 0) {
		hostname_cache_insert(addr, family, hostname);
		cached = hostname_cache_lookup(addr, family);
		return cached ? cached->hostname : fallback_ip;
	}

	/* Cache the IP address itself to avoid repeated failed lookups */
	hostname_cache_insert(addr, family, fallback_ip);
	return fallback_ip;
}

static void flow_key_to_display_strings(const struct flow_key *key,
					char *src_display, size_t src_len,
					char *dst_display, size_t dst_len)
{
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	const char *src_name, *dst_name;

	flow_key_to_strings(key, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

	src_name = resolve_hostname((struct flow_addr *)&key->src, key->family, src_ip);
	dst_name = resolve_hostname((struct flow_addr *)&key->dst, key->family, dst_ip);

	strncpy(src_display, src_name, src_len - 1);
	src_display[src_len - 1] = '\0';
	strncpy(dst_display, dst_name, dst_len - 1);
	dst_display[dst_len - 1] = '\0';
}

static struct ndpi_flow *flow_table_insert(struct flow_key *key)
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

	flow->next = flow_table[hash];
	flow_table[hash] = flow;

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
}

static void setup_signals(void)
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
}

static int get_interface_ip(const char *ifname)
{
	struct ifaddrs *ifaddr, *ifa;
	int found = 0;

	if (getifaddrs(&ifaddr) == -1) {
		fprintf(stderr, "Failed to get interface addresses: %s\n", strerror(errno));
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, ifname) == 0) {
			if (ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
				struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

				local_ip_family = FLOW_FAMILY_IPV4;
				local_ip.hi = 0;
				local_ip.lo = (__u64)addr->sin_addr.s_addr;

				if (netmask)
					local_subnet_mask = netmask->sin_addr.s_addr;

				found = 1;

				char ip_str[INET_ADDRSTRLEN];
				char mask_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));

				if (netmask) {
					inet_ntop(AF_INET, &netmask->sin_addr, mask_str, sizeof(mask_str));
					fprintf(stderr, "Interface %s IPv4: %s/%s (hostname resolution enabled)\n",
						ifname, ip_str, mask_str);
				} else {
					fprintf(stderr, "Interface %s IPv4: %s (hostname resolution enabled)\n",
						ifname, ip_str);
				}
				break;
			} else if (ifa->ifa_addr->sa_family == AF_INET6 && !found) {
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
				local_ip_family = FLOW_FAMILY_IPV6;
				memcpy(&local_ip, &addr6->sin6_addr, sizeof(struct in6_addr));
				found = 1;

				char ip_str[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &addr6->sin6_addr, ip_str, sizeof(ip_str));
				fprintf(stderr, "Interface %s IPv6: %s (hostname resolution enabled)\n", ifname, ip_str);
			}
		}
	}

	freeifaddrs(ifaddr);

	if (!found) {
		fprintf(stderr, "Warning: Could not determine IP address for %s\n", ifname);
	}

	return found ? 0 : -1;
}

static int should_filter_flow(struct flow_key *key)
{
	if (key->family == FLOW_FAMILY_IPV4) {
		__u32 dst_ip = (__u32)key->dst.lo;
		if (dst_ip == 0xFFFFFFFF)
			return 1;
	}

	if (local_ip_family != 0 && (key->src_port == 6379 || key->dst_port == 6379)) {
		if (key->family == local_ip_family) {
			if (key->family == FLOW_FAMILY_IPV4) {
				if (key->src.lo == local_ip.lo || key->dst.lo == local_ip.lo)
					return 1;
			} else if (key->family == FLOW_FAMILY_IPV6) {
				if ((key->src.hi == local_ip.hi && key->src.lo == local_ip.lo) ||
				    (key->dst.hi == local_ip.hi && key->dst.lo == local_ip.lo))
					return 1;
			}
		}
	}

	return 0;
}

static void emit_classification_event(struct ndpi_flow *flow, const char *ifname)
{
	struct blob_buf b = {};
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	const char *master_name, *app_name, *category_name;
	struct flow_key summary_key;

	if (!ubus_ctx)
		return;

	/* Use first packet key for consistent reporting across flow direction changes */
	if (flow->have_first_packet_key)
		summary_key = flow->first_packet_key;
	else
		summary_key = flow->key;

	flow_key_to_strings(&summary_key, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

	if (flow->protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
		master_name = ndpi_get_proto_name(ndpi, flow->protocol.proto.app_protocol);
	else
		master_name = ndpi_get_proto_name(ndpi, flow->protocol.proto.master_protocol);
	app_name = ndpi_get_proto_name(ndpi, flow->protocol.proto.app_protocol);
	category_name = ndpi_category_get_name(ndpi, flow->protocol.category);

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
			blobmsg_add_string(&b, NULL, ndpi_get_proto_name(ndpi, flow->protocol_stack[i]));
		blobmsg_close_array(&b, stack);
	}

	if (ubus_send_event(ubus_ctx, "classifi.classified", b.head) != 0) {
		if (verbose)
			fprintf(stderr, "Failed to send ubus event for flow %s:%u -> %s:%u\n",
				src_ip, summary_key.src_port, dst_ip, summary_key.dst_port);
	}

	blob_buf_free(&b);
}

static struct ndpi_detection_module_struct *setup_ndpi(void)
{
	struct ndpi_detection_module_struct *ndpi_struct;

	ndpi_struct = ndpi_init_detection_module(NULL);
	if (!ndpi_struct) {
		fprintf(stderr, "Failed to initialize nDPI\n");
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
		fprintf(stderr, "Failed to finalize nDPI initialization\n");
		ndpi_exit_detection_module(ndpi_struct);
		return NULL;
	}

	printf("Initialized nDPI version %s with enhanced configuration\n",
	       ndpi_revision());

	return ndpi_struct;
}

static void classify_packet(struct packet_sample *sample)
{
	struct ndpi_flow *flow;
	ndpi_protocol protocol;
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	struct flow_key packet_view;
	struct ndpi_flow_input_info input_info = {0};
	static int total_samples = 0;

	total_samples++;

	if (should_filter_flow(&sample->key))
		return;

	packet_view = sample->key;
	if (sample->direction)
		swap_flow_endpoints(&packet_view);

	flow_key_to_strings(&packet_view, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

	flow = flow_table_lookup(&sample->key);
	if (!flow) {
		flow = flow_table_insert(&sample->key);
		if (!flow) {
			fprintf(stderr, "Failed to create flow for %s:%u -> %s:%u\n",
				src_ip, packet_view.src_port,
				dst_ip, packet_view.dst_port);
			return;
		}
		if (verbose) {
			fprintf(stderr, "New flow: %s:%u -> %s:%u proto=%u\n",
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

	if (verbose) {
		fprintf(stderr, "Sample %d (flow pkt %d, dir=%u): %s:%u -> %s:%u proto=%u len=%u l3_off=%u [dir0=%d dir1=%d]\n",
			total_samples, flow->packets_processed, sample->direction,
			src_ip, packet_view.src_port,
			dst_ip, packet_view.dst_port, packet_view.protocol,
			sample->data_len, sample->l3_offset,
			flow->packets_dir0, flow->packets_dir1);

		if (flow->packets_processed == 1 || flow->packets_processed == 2) {
			fprintf(stderr, "  Packet %d hex dump (first 64 bytes):\n  ", flow->packets_processed);
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
		if (verbose)
			fprintf(stderr, "  Packet shorter than L3 offset (%u), skipping\n", l3_offset);
		return;
	}

	u_int64_t time_ms = sample->ts_ns ? sample->ts_ns / 1000000ULL : (u_int64_t)time(NULL) * 1000ULL;

	protocol = ndpi_detection_process_packet(
		ndpi, flow->flow, ip_packet, ip_packet_len,
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

	if (verbose) {
		fprintf(stderr, "  [PKT %d] nDPI process_packet: master=%u (%s) app=%u (%s) category=%s state=%d\n",
			flow->packets_processed,
			protocol.proto.master_protocol,
			ndpi_get_proto_name(ndpi, protocol.proto.master_protocol),
			protocol.proto.app_protocol,
			ndpi_get_proto_name(ndpi, protocol.proto.app_protocol),
			ndpi_category_get_name(ndpi, protocol.category),
			protocol.state);

		/* Show TCP fingerprint if available */
		if (flow->tcp_fingerprint[0]) {
			fprintf(stderr, "  [TCP FP] %s (OS: %s)\n",
				flow->tcp_fingerprint, flow->os_hint);
		}

		/* Show protocol stack if multi-layer */
		if (flow->protocol_stack_count > 1) {
			fprintf(stderr, "  [Stack] ");
			for (int i = 0; i < flow->protocol_stack_count; i++) {
				fprintf(stderr, "%s%s", i > 0 ? " -> " : "",
					ndpi_get_proto_name(ndpi, flow->protocol_stack[i]));
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

			stats = dns_lookup(client_addr, packet_view.family);
			if (!stats)
				stats = dns_insert(client_addr, packet_view.family);

			if (stats) {
				if (packet_view.dst_port == 53) {
					stats->queries++;
					if (extract_dns_query_name(dns_payload, dns_len, query_name, sizeof(query_name)) == 0) {
						strncpy(stats->last_query, query_name, sizeof(stats->last_query) - 1);
						if (verbose)
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
		if (verbose) {
			fprintf(stderr, "  [PKT %d] Flow finalized via nDPI state=%d\n",
				flow->packets_processed, protocol.state);
		}
	}

	int packets_threshold = pcap_mode ? 50 : PACKETS_TO_SAMPLE;

	if (!flow->detection_finalized && flow->packets_processed >= packets_threshold) {
		if (verbose)
			fprintf(stderr, "  [PKT %d] Calling ndpi_detection_giveup() [dir0=%d dir1=%d]...\n",
				flow->packets_processed, flow->packets_dir0, flow->packets_dir1);

		protocol = ndpi_detection_giveup(ndpi, flow->flow);
		flow->detection_finalized = 1;
		flow->protocol_guessed = (protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN);

		if (verbose) {
			fprintf(stderr, "  [PKT %d] After giveup (guessed=%d, dir0=%d dir1=%d): master=%u (%s) app=%u (%s)\n",
				flow->packets_processed,
				flow->protocol_guessed, flow->packets_dir0, flow->packets_dir1,
				protocol.proto.master_protocol,
				ndpi_get_proto_name(ndpi, protocol.proto.master_protocol),
				protocol.proto.app_protocol,
				ndpi_get_proto_name(ndpi, protocol.proto.app_protocol));
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

			if (verbose) {
				fprintf(stderr, "  [PKT %d] Classification changed: old master=%u app=%u -> new master=%u app=%u\n",
					flow->packets_processed,
					flow->protocol.proto.master_protocol,
					flow->protocol.proto.app_protocol,
					protocol.proto.master_protocol,
					protocol.proto.app_protocol);
			}
		}

		flow->protocol = protocol;

		if (newly_classified && attached_ifname)
			emit_classification_event(flow, attached_ifname);
	}
}

static int handle_sample(void *ctx, void *data, size_t len)
{
	struct packet_sample *sample = data;

	if (len < sizeof(*sample))
		return 0;

	classify_packet(sample);
	return 0;
}

static void detach_tc_program(void)
{
	LIBBPF_OPTS(bpf_tc_hook, hook);
	LIBBPF_OPTS(bpf_tc_opts, opts);
	int ret;

	if (!attached_ifindex || !attached_ifname)
		return;

	hook.ifindex = attached_ifindex;
	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

	hook.attach_point = BPF_TC_INGRESS;
	opts.flags = 0;
	opts.prog_fd = 0;
	opts.prog_id = 0;
	ret = bpf_tc_detach(&hook, &opts);
	if (ret && ret != -ENOENT)
		fprintf(stderr, "Warning: Failed to detach TC program from ingress: %s\n", strerror(-ret));

	hook.attach_point = BPF_TC_EGRESS;
	ret = bpf_tc_detach(&hook, &opts);
	if (ret && ret != -ENOENT)
		fprintf(stderr, "Warning: Failed to detach TC program from egress: %s\n", strerror(-ret));

	printf("Detached BPF program from %s (ifindex %d)\n", attached_ifname, attached_ifindex);
}

static int attach_tc_program(int prog_fd, const char *ifname)
{
	int ifindex;
	LIBBPF_OPTS(bpf_tc_hook, hook);
	LIBBPF_OPTS(bpf_tc_opts, opts_ingress);
	LIBBPF_OPTS(bpf_tc_opts, opts_egress);
	int ret;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Failed to get ifindex for %s: %s\n",
			ifname, strerror(errno));
		return -1;
	}

	hook.ifindex = ifindex;
	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

	ret = bpf_tc_hook_create(&hook);
	if (ret && ret != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-ret));
		return ret;
	}

	hook.attach_point = BPF_TC_INGRESS;
	opts_ingress.prog_fd = prog_fd;
	opts_ingress.flags = BPF_TC_F_REPLACE;
	ret = bpf_tc_attach(&hook, &opts_ingress);
	if (ret) {
		fprintf(stderr, "Failed to attach TC program to ingress: %s\n", strerror(-ret));
		return ret;
	}

	hook.attach_point = BPF_TC_EGRESS;
	opts_egress.prog_fd = prog_fd;
	opts_egress.flags = BPF_TC_F_REPLACE;
	ret = bpf_tc_attach(&hook, &opts_egress);
	if (ret) {
		fprintf(stderr, "Failed to attach TC program to egress: %s\n", strerror(-ret));
		return ret;
	}

	printf("Attached BPF program to %s ingress+egress (ifindex %d)\n", ifname, ifindex);

	attached_ifname = ifname;
	attached_ifindex = ifindex;

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

static void print_dns_summary(void)
{
	char client_ip[INET6_ADDRSTRLEN];
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char timestamp[20];
	int total_clients = 0;

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

	printf("\n=== DNS Summary ===\n");

	for (int i = 0; i < DNS_TABLE_SIZE; i++) {
		struct dns_stats *stats = dns_table[i];
		while (stats) {
			/* Convert client IP to string or hostname for local subnet */
			const char *display_ip;
			if (stats->family == FLOW_FAMILY_IPV4) {
				struct in_addr addr = { .s_addr = (__u32)stats->client_ip.lo };
				inet_ntop(AF_INET, &addr, client_ip, sizeof(client_ip));
				display_ip = resolve_hostname(&stats->client_ip, stats->family, client_ip);
			} else if (stats->family == FLOW_FAMILY_IPV6) {
				struct in6_addr addr6;
				memcpy(&addr6, &stats->client_ip, sizeof(addr6));
				inet_ntop(AF_INET6, &addr6, client_ip, sizeof(client_ip));
				display_ip = resolve_hostname(&stats->client_ip, stats->family, client_ip);
			} else {
				snprintf(client_ip, sizeof(client_ip), "unknown");
				display_ip = client_ip;
			}

			printf("%s | %-39s | Q:%-5llu R:%-5llu | Last: %s\n",
			       timestamp, display_ip,
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

static void print_classified_flows(void)
{
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	const char *master_name, *app_name;
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char timestamp[20];

	struct flow_key summary_key;

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

	for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
		struct ndpi_flow *flow = flow_table[i];
		while (flow) {
			if (flow->protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
			    flow->protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {

				if (flow->have_first_packet_key)
					summary_key = flow->first_packet_key;
				else
					summary_key = flow->key;

				flow_key_to_display_strings(&summary_key, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

				/* In nDPI 4.14+, master_protocol is only set for nested protocols */
				if (flow->protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
					master_name = ndpi_get_proto_name(ndpi, flow->protocol.proto.app_protocol);
				else
					master_name = ndpi_get_proto_name(ndpi, flow->protocol.proto.master_protocol);
				app_name = ndpi_get_proto_name(ndpi, flow->protocol.proto.app_protocol);

				if (suppress_noisy) {
					if (flow->protocol.proto.app_protocol == NDPI_PROTOCOL_DNS ||
					    summary_key.protocol == IPPROTO_ICMP ||
					    summary_key.protocol == IPPROTO_ICMPV6 ||
					    summary_key.protocol == 2) {
						flow = flow->next;
						continue;
					}
				}

				const char *category_name = ndpi_category_get_name(ndpi, flow->protocol.category);

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

	/* Print DNS summary if we have DNS traffic */
	if (suppress_noisy)
		print_dns_summary();
}

static void cleanup_expired_flows(int flow_map_fd)
{
	time_t now = time(NULL);
	int total_flows = 0;
	int expired_flows = 0;

	for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
		struct ndpi_flow **prev = &flow_table[i];
		struct ndpi_flow *flow = flow_table[i];

		while (flow) {
			total_flows++;

			time_t idle_time = now - flow->last_seen;
			time_t age = now - flow->first_seen;

			int should_expire = 0;
			if (idle_time >= FLOW_IDLE_TIMEOUT) {
				should_expire = 1;
				if (verbose)
					fprintf(stderr, "Expiring idle flow (idle %ld sec)\n", idle_time);
			} else if (age >= FLOW_ABSOLUTE_TIMEOUT) {
				should_expire = 1;
				if (verbose)
					fprintf(stderr, "Expiring old flow (age %ld sec)\n", age);
			}

			if (should_expire) {
				struct ndpi_flow *to_free = flow;

				*prev = flow->next;
				flow = flow->next;

				if (flow_map_fd >= 0)
					bpf_map_delete_elem(flow_map_fd, &to_free->key);

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

	if (verbose && expired_flows > 0) {
		fprintf(stderr, "Flow cleanup: %d active, %d expired\n",
			total_flows - expired_flows, expired_flows);
	}
}

static void pcap_packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr,
				const unsigned char *packet)
{
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

	if (should_filter_flow(&key))
		return;

	packet_view = key;
	if (direction)
		swap_flow_endpoints(&packet_view);

	flow_key_to_strings(&packet_view, src_ip, sizeof(src_ip), dst_ip, sizeof(dst_ip));

	flow = flow_table_lookup(&key);
	if (!flow) {
		flow = flow_table_insert(&key);
		if (!flow) {
			fprintf(stderr, "Failed to create flow for %s:%u -> %s:%u\n",
				src_ip, packet_view.src_port,
				dst_ip, packet_view.dst_port);
			return;
		}
		if (verbose) {
			fprintf(stderr, "New flow: %s:%u -> %s:%u proto=%u\n",
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

	if (verbose && (flow->packets_processed <= 50 || flow->packets_processed % 20 == 0)) {
		fprintf(stderr, "Packet %llu (flow pkt %d, dir=%u): %s:%u -> %s:%u proto=%u len=%u [dir0=%d dir1=%d]\n",
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
		if (verbose)
			fprintf(stderr, "  No L3 data, skipping nDPI\n");
		return;
	}

	u_int64_t time_ms = pkthdr->ts.tv_sec * 1000ULL + pkthdr->ts.tv_usec / 1000ULL;

	protocol = ndpi_detection_process_packet(
		ndpi, flow->flow, l3_data, l3_len,
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

	if (verbose && (flow->packets_processed <= 50 || flow->packets_processed % 20 == 0)) {
		fprintf(stderr, "  [PKT %d] nDPI process_packet: master=%u (%s) app=%u (%s) category=%s state=%d\n",
			flow->packets_processed,
			protocol.proto.master_protocol,
			ndpi_get_proto_name(ndpi, protocol.proto.master_protocol),
			protocol.proto.app_protocol,
			ndpi_get_proto_name(ndpi, protocol.proto.app_protocol),
			ndpi_category_get_name(ndpi, protocol.category),
			protocol.state);

		/* Show TCP fingerprint if available */
		if (flow->tcp_fingerprint[0]) {
			fprintf(stderr, "  [TCP FP] %s (OS: %s)\n",
				flow->tcp_fingerprint, flow->os_hint);
		}

		/* Show protocol stack if multi-layer */
		if (flow->protocol_stack_count > 1) {
			fprintf(stderr, "  [Stack] ");
			for (int i = 0; i < flow->protocol_stack_count; i++) {
				fprintf(stderr, "%s%s", i > 0 ? " -> " : "",
					ndpi_get_proto_name(ndpi, flow->protocol_stack[i]));
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

			if (packet_view.src_port == 53) {
				client_addr = &packet_view.dst;
			} else {
				client_addr = &packet_view.src;
			}

			stats = dns_lookup(client_addr, packet_view.family);
			if (!stats)
				stats = dns_insert(client_addr, packet_view.family);

			if (stats) {
				if (packet_view.dst_port == 53) {
					stats->queries++;
					if (extract_dns_query_name(dns_payload, dns_len, query_name, sizeof(query_name)) == 0) {
						strncpy(stats->last_query, query_name, sizeof(stats->last_query) - 1);
						if (verbose)
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
		if (verbose) {
			fprintf(stderr, "  [PKT %d] Flow finalized via nDPI state=%d\n",
				flow->packets_processed, protocol.state);
		}
	}

	if (!flow->detection_finalized && flow->packets_processed >= 50) {
		if (verbose)
			fprintf(stderr, "  [PKT %d] Calling ndpi_detection_giveup() [dir0=%d dir1=%d]...\n",
				flow->packets_processed, flow->packets_dir0, flow->packets_dir1);

		protocol = ndpi_detection_giveup(ndpi, flow->flow);
		flow->detection_finalized = 1;
		flow->protocol_guessed = (protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN);

		if (verbose) {
			fprintf(stderr, "  [PKT %d] After giveup (guessed=%d, dir0=%d dir1=%d): master=%u (%s) app=%u (%s)\n",
				flow->packets_processed,
				flow->protocol_guessed, flow->packets_dir0, flow->packets_dir1,
				protocol.proto.master_protocol,
				ndpi_get_proto_name(ndpi, protocol.proto.master_protocol),
				protocol.proto.app_protocol,
				ndpi_get_proto_name(ndpi, protocol.proto.app_protocol));
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
		}

		flow->protocol = protocol;

		if (newly_classified && attached_ifname)
			emit_classification_event(flow, attached_ifname);
	}
}

static int run_pcap_mode(const char *ifname)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	fprintf(stderr, "Starting libpcap capture on %s\n", ifname);
	fprintf(stderr, "WARNING: This mode captures ALL packets and is CPU-intensive!\n");
	fprintf(stderr, "Press Ctrl+C to stop\n\n");

	handle = pcap_open_live(ifname, 65535, 1, 100, errbuf);
	if (!handle) {
		fprintf(stderr, "Failed to open interface %s: %s\n", ifname, errbuf);
		return -1;
	}

	time_t last_cleanup = time(NULL);
	while (keep_running) {
		int ret = pcap_dispatch(handle, 100, pcap_packet_handler, NULL);

		if (ret < 0) {
			fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
			break;
		}

		time_t now = time(NULL);
		if (now - last_cleanup >= CLEANUP_INTERVAL) {
			cleanup_expired_flows(-1);
			last_cleanup = now;
		}
	}

	pcap_close(handle);
	return 0;
}

static void print_ringbuf_stats(int ringbuf_stats_fd, __u64 *last_drops)
{
	__u32 key = 0;
	__u64 drops = 0;

	if (bpf_map_lookup_elem(ringbuf_stats_fd, &key, &drops) == 0) {
		if (drops > *last_drops) {
			__u64 new_drops = drops - *last_drops;
			fprintf(stderr, "WARNING: Ring buffer dropped %llu packet samples (total: %llu)\n",
				new_drops, drops);
			*last_drops = drops;
		}
	}
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct ring_buffer *rb = NULL;
	int prog_fd, flow_map_fd, samples_fd, ringbuf_stats_fd;
	int err = 0;
	const char *ifname;
	const char *bpf_obj_path;
	time_t last_stats = 0;
	int opt_idx = 1;

	while (opt_idx < argc && argv[opt_idx][0] == '-') {
		if (strcmp(argv[opt_idx], "-v") == 0 ||
		    strcmp(argv[opt_idx], "--verbose") == 0) {
			verbose = 1;
			opt_idx++;
		} else if (strcmp(argv[opt_idx], "-s") == 0 ||
		           strcmp(argv[opt_idx], "--stats") == 0) {
			periodic_stats = 1;
			opt_idx++;
		} else if (strcmp(argv[opt_idx], "-p") == 0 ||
		           strcmp(argv[opt_idx], "--pcap") == 0) {
			pcap_mode = 1;
			opt_idx++;
		} else if (strcmp(argv[opt_idx], "-n") == 0 ||
		           strcmp(argv[opt_idx], "--noisy") == 0) {
			suppress_noisy = 0;
			opt_idx++;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[opt_idx]);
			fprintf(stderr, "Usage: %s [-v|--verbose] [-s|--stats] [-p|--pcap] [-n|--noisy] <interface> [bpf_object.o]\n", argv[0]);
			return 1;
		}
	}

	if (pcap_mode) {
		if (argc - opt_idx < 1) {
			fprintf(stderr, "Usage (pcap mode): %s [-v] [-s] [-n] -p <interface>\n", argv[0]);
			return 1;
		}
		ifname = argv[opt_idx];
		bpf_obj_path = NULL;
	} else {
		if (argc - opt_idx < 2) {
			fprintf(stderr, "Usage (eBPF mode): %s [-v] [-s] [-n] <interface> <bpf_object.o>\n", argv[0]);
			return 1;
		}
		ifname = argv[opt_idx];
		bpf_obj_path = argv[opt_idx + 1];
	}

	setup_signals();

	uloop_init();
	ubus_ctx = ubus_connect(NULL);
	if (!ubus_ctx) {
		fprintf(stderr, "Warning: Failed to connect to ubus, events will not be emitted\n");
	} else {
		ubus_add_uloop(ubus_ctx);
		if (verbose)
			fprintf(stderr, "Connected to ubus for event emission\n");
	}

	get_interface_ip(ifname);

	ndpi = setup_ndpi();
	if (!ndpi) {
		fprintf(stderr, "Failed to initialize nDPI\n");
		return 1;
	}

	if (pcap_mode) {
		attached_ifname = ifname;
		err = run_pcap_mode(ifname);
		goto cleanup;
	}

	obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Failed to open BPF object: %s\n", bpf_obj_path);
		return 1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "Failed to load BPF object\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "classifi");
	if (!prog) {
		fprintf(stderr, "Failed to find classifi program\n");
		goto cleanup;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to get program fd\n");
		goto cleanup;
	}

	flow_map_fd = bpf_object__find_map_fd_by_name(obj, "flow_map");
	samples_fd = bpf_object__find_map_fd_by_name(obj, "packet_samples");
	ringbuf_stats_fd = bpf_object__find_map_fd_by_name(obj, "ringbuf_stats");

	if (flow_map_fd < 0 || samples_fd < 0 || ringbuf_stats_fd < 0) {
		fprintf(stderr, "Failed to find BPF maps\n");
		goto cleanup;
	}

	if (attach_tc_program(prog_fd, ifname) < 0) {
		fprintf(stderr, "Failed to attach program to interface\n");
		goto cleanup;
	}

	rb = ring_buffer__new(samples_fd, handle_sample, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Classifier running on interface %s\n", ifname);
	printf("Press Ctrl+C to stop\n\n");

	time_t last_cleanup = time(NULL);
	__u64 last_ringbuf_drops = 0;

	__u32 stats_key = 0;
	bpf_map_lookup_elem(ringbuf_stats_fd, &stats_key, &last_ringbuf_drops);
	while (keep_running) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}

		time_t now = time(NULL);
		if (now - last_stats >= 10) {
			print_ringbuf_stats(ringbuf_stats_fd, &last_ringbuf_drops);
			last_stats = now;
		}

		if (now - last_cleanup >= CLEANUP_INTERVAL) {
			cleanup_expired_flows(flow_map_fd);
			last_cleanup = now;
		}
	}

	printf("\nShutting down...\n");

cleanup:
	detach_tc_program();
	ring_buffer__free(rb);
	bpf_object__close(obj);
	if (ndpi)
		ndpi_exit_detection_module(ndpi);

	if (ubus_ctx) {
		ubus_free(ubus_ctx);
		ubus_ctx = NULL;
	}
	uloop_done();

	return err != 0;
}
