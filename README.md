# NetWatch on FreeBSD / OPNsense

A FreeBSD port of [NetWatch](https://github.com/matthart1983/netwatch), a Rust
terminal network monitor. I built it to run on my OPNsense router and validated
it there. The original project README is in
[`docs/UPSTREAM_README.md`](docs/UPSTREAM_README.md).

**Branches**

| Branch | What it is |
|---|---|
| `main` | The FreeBSD port, built on NetWatch 0.30.4, one commit per change |
| `opnsense-interface-descriptions` | One feature rebuilt on current upstream (0.35.x) as a contribution-ready change |

## The problem

On OPNsense, NetWatch's packet capture failed at startup:

```
ERROR netwatch::capture: pcap open failed interface=en0 error=libpcap error: No such device exists
```

Plain `tcpdump -ni vtnet1` worked, and so did NetWatch once I set
`capture_interface = "vtnet1"`. That ruled out libpcap, BPF, the Rust toolchain
and the FreeBSD version. The fault was in how NetWatch picked a default
interface. `ktrace` confirmed which device it was trying to open.

## Root cause

NetWatch's platform layer had implementations for Linux, macOS and Windows.
On FreeBSD every call fell through to the "unsupported platform" branch:

1. `collect_interface_info()` failed, and the caller turned that into an empty list.
2. `default_route_interface()` returned nothing.
3. The interface picker, given an empty list and no route hint, fell through to
   its last-resort literal: `"en0"`, a macOS interface name.

Swapping `en0` for `vtnet0` would have just traded one hard-coded name for
another. The fix had to be interface discovery that works on any FreeBSD NIC:
`vtnet`, `em`, `igb`, `ix`, VLANs, WireGuard.

## What I built

Each change is a self-contained commit with tests:

| Commit | Change | FreeBSD mechanism |
|---|---|---|
| Interface discovery | Enumerate interfaces; choose the one that carries the default route; skip `lo0`/`pflog`/`pfsync`/`enc`/`usbus`; never open a device that doesn't exist | `getifaddrs(3)`, `route -n get default` |
| Interface stats | Per-interface rx/tx counters, errors, drops, link speed | `if_data` from `getifaddrs`: one call per refresh, no `netstat` subprocess |
| OPNsense descriptions | Interfaces tab shows WAN / LAN / CLIENTS / IOT instead of `ethernet` | Kernel interface description (`ifdescr`) |
| Process attribution | Connections and processes tabs filled in. Linux uses eBPF here, which FreeBSD doesn't have | `sockstat -46` on the existing background collector thread, never on the capture path |
| Privsep dedup | Merge duplicate rows where privilege-separated sshd processes share one socket, keeping IPv4 and IPv6 listeners on the same port separate | 5-tuple dedup keyed on the raw protocol token |
| Full process names | `sshd-sessi` becomes `sshd-session` (sockstat cuts names at its column width) | `sysctl kern.proc.pathname.<pid>` |

## Validation

- **Real hardware.** Ran on OPNsense 15.1 (FreeBSD 15.1-RELEASE) with a WAN, a LAN,
  six VLANs and WireGuard. Auto-selection picked the WAN. The interfaces tab
  showed live per-VLAN rates and the OPNsense names. Connections showed
  attributed daemons (`sshd-session`, `lighttpd`, `ntpd`).
- **Full test suite on FreeBSD.** 958 passing, 0 failing (2 ignored live-hardware
  tests). The first full run caught a real regression: a test assumed FreeBSD
  had no process-name resolver, and my last commit had added one. I fixed it by
  moving FreeBSD to the right side of a paired test, not by weakening the
  assertion.
- **Real data in the tests.** The `sockstat` parser is tested against verbatim
  output from the router. That's how I found the privsep duplicate rows.
- **Cross-platform safety.** The struct field and enum variant I added are
  set in every Linux, macOS and Windows code path, so the other platforms
  still build.

## Design decisions

- **Prefer kernel interfaces to text scraping** where it's practical: `getifaddrs`,
  `if_data`, `sysctl`. Where a subprocess was the right tool (`sockstat`), it
  runs at most once a second on a background thread, so it can't stall packet
  capture on a busy router.
- **Prefer an explicit "nothing found" to a guess.** With no capturable interface,
  NetWatch now says so instead of opening a nonexistent device.
- **Guard the edge cases.** On FreeBSD, `sysctl kern.proc.pathname` with pid
  `-1` means "the current process". A pid that overflows into `-1` would
  quietly return NetWatch's own path, so out-of-range pids are rejected before
  the call.
- **No OPNsense dependency.** Descriptions come from the kernel, not OPNsense's
  config files, so stock FreeBSD gets the same build and simply shows no
  descriptions.

## Upstream

While I worked on this, the maintainer independently added FreeBSD support
upstream (v0.35.0). It arrived at most of the same design: `sockstat`
attribution, `route get` interface selection, `getifaddrs` up-state, and the
same out-of-range pid guard on `sysctl`. Rather than submit duplicate work, I
compared the two. The one capability upstream didn't have was OPNsense
interface descriptions. The `opnsense-interface-descriptions` branch rebuilds
that feature on current upstream. It reads the `description:` line from the
`ifconfig` output upstream already parses, so there's no extra command, and
the description is sanitized the same way upstream sanitizes interface names.

## Build and deploy

```sh
# FreeBSD 15.1 build VM (same major release as the router: libpcap ABI)
cargo build --release --no-default-features
scp target/release/netwatch root@router:/usr/local/bin/netwatch
```

See [`docs/FREEBSD.md`](docs/FREEBSD.md) for configuration, how the default
interface is chosen, and known limitations.

---

Andy Alexander · [github.com/greenbeanorg](https://github.com/greenbeanorg)
