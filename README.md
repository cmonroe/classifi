# eBPF + nDPI Traffic Classifier for OpenWrt

A hybrid network traffic classifier that combines eBPF for flow tracking with nDPI for deep packet inspection.

## Architecture

```
  ╔══════════════════════════════════════════════════════════════╗
  ║                    USER SPACE  (nDPI)                        ║
  ╠══════════════════════════════════════════════════════════════╣
  ║                                                              ║
  ║  classifi.c + classifi_ubus.c                                ║
  ║  ▸ load/attach BPF (libbpf)                                  ║
  ║  ▸ poll ring buffer                                          ║
  ║  ▸ maintain flow hash table                                  ║
  ║  ▸ multi-interface management                                ║
  ║                                                              ║
  ║    ╭──────────────────╮       ╭─────────────────────╮        ║
  ║    │ Flow Table       │◀──────│ nDPI v5.0           │        ║
  ║    │  · nDPI contexts │       │  · classification   │        ║
  ║    │  · protocol IDs  │       │  · TCP fingerprint  │        ║
  ║    │  · TCP fprint    │       │  · protocol stack   │        ║
  ║    │  · timestamps    │       │  · master/app/cat   │        ║
  ║    │ expire: 30s/60s  │       ╰─────────────────────╯        ║
  ║    ╰────────┬─────────╯                                      ║
  ║             │                                                ║
  ║             ├──▶ ubus event: classifi.classified             ║
  ║             ├──▶ ubus event: classifi.rule_match             ║
  ║             ├──▶ ubus event: classifi.dns_query              ║
  ║             └──▶ ubus API: status, get_flows, etc.           ║
  ║                                          │                   ║
  ╠══════════════════════════════════════════╪═══════════════════╣
  ║                                          │ zero-copy         ║
  ╠══════════════════════════════════════════╪═══════════════════╣
  ║                    KERNEL SPACE  (eBPF)  │                   ║
  ╠══════════════════════════════════════════╪═══════════════════╣
  ║                                          ▼                   ║
  ║  classifi.bpf.c (TC program)                                 ║
  ║  ▸ parse packets (Eth→VLAN→IPv4/6→TCP/UDP)                   ║
  ║  ▸ extract & canonicalize 5-tuple                            ║
  ║  ▸ track flow state per interface                            ║
  ║                                                              ║
  ║    ╭─────────────────╮         ╭──────────────────╮          ║
  ║    │  flow_map       │         │ packet_samples   │          ║
  ║    │  (hash)         │         │ (ring buffer)    │          ║
  ║    │  8192 flows     │         │ 1MB / 50 pkts    │          ║
  ║    │  stats/state    │         │ per flow         │          ║
  ║    ╰─────────────────╯         ╰──────────────────╯          ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
                              ▲
            ┌─────────────────┼─────────────────┐
            │                 │                 │
       TC INGRESS        TC EGRESS        (per interface)
            │                 │                 │
            └─────────────────┴─────────────────┘
                              ▲
                     NETWORK INTERFACES
```

## Features

- Low overhead kernel-space flow tracking via eBPF TC hooks
- IPv4/IPv6, TCP/UDP with VLAN unwrapping (802.1Q/802.1AD)
- Multi-interface support (up to 8 interfaces, auto-discovery from UCI)
- nDPI 5.0 protocol detection with TCP fingerprinting and OS hints
- Custom traffic match rules with regex extraction and script triggers
- DNS query event reporting with query type classification
- Real-time ubus events and query API
- Dynamic configuration reload without restart

## Dependencies

- libbpf, libelf, zlib
- libndpi (5.0+)
- libubus, libubox, libblobmsg-json, libuci
- kmod-sched-core, kmod-sched-bpf

## Building

```bash
cp -r classifi <openwrt>/package/
cd <openwrt>
make menuconfig  # Network -> classifi
make package/classifi/compile V=s
```

## Usage

### Command Line

```bash
classifi -i br-lan /usr/lib/bpf/classifi.bpf.o              # single interface
classifi -i br-lan -i br-guest /usr/lib/bpf/classifi.bpf.o  # multiple
classifi -d /usr/lib/bpf/classifi.bpf.o                     # auto-discover LAN interfaces
classifi -v -s -i br-lan /usr/lib/bpf/classifi.bpf.o        # verbose + stats
```

Options: `-i <iface>` (repeatable), `-d` (discover), `-v` (verbose), `-s` (stats), `-p` (pcap mode)

### Service (UCI)

```bash
uci set classifi.config=classifi
uci set classifi.config.discover='1'
uci set classifi.config.enabled='1'
uci commit classifi
/etc/init.d/classifi enable && /etc/init.d/classifi start
```

## ubus API

| Method | Description |
|--------|-------------|
| `status` | Daemon mode, interfaces, ring buffer stats |
| `get_flows` | All classified flows with protocol/category info |
| `reload_config` | Hot reload interfaces and rules from UCI |

### Events

- `classifi.classified` - Flow classification complete (protocol, category, OS hint)
- `classifi.rule_match` - Custom rule matched (includes regex captures)
- `classifi.dns_query` - DNS query observed (domain, query type)

```bash
ubus call classifi status
ubus listen classifi.classified
```

## Traffic Match Rules

Custom rules match traffic patterns, extract data via regex, and trigger actions:

```
config rule 'session_capture'
    option enabled '1'
    option name 'http_session'
    option dst_port '8080'
    option protocol 'tcp'
    option host_header 'api.example.com'
    option pattern 'POST /session/([a-f0-9-]+)'
    option script '/usr/libexec/classifi/handler.sh'
```

Options: `dst_ip`, `dst_port`, `protocol`, `host_header`, `pattern` (regex with up to 4 capture groups), `script`

On match, emits `classifi.rule_match` event and optionally executes script with `CLASSIFI_MATCH_1..4` environment variables.

## License

GPL-2.0

## References

- [eBPF Documentation](https://ebpf.io/)
- [libbpf](https://github.com/libbpf/libbpf)
- [nDPI](https://github.com/ntop/nDPI)
