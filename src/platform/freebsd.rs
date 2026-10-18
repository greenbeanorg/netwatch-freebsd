//! FreeBSD / OPNsense interface enumeration and default-route lookup.
//!
//! Before this module existed, FreeBSD had no `platform::*` implementation:
//! every entry point fell through to the `not(any(linux, macos, windows))`
//! arm, so `collect_interface_info()` returned `Unsupported platform` and the
//! capture-interface picker (`App::pick_capture_interface`) had an empty slice
//! and no default-route hint to work with — landing it on its hard-coded
//! macOS-shaped `en0` fallback, which doesn't exist on FreeBSD.
//!
//! Enumeration uses `getifaddrs(3)` via `nix` (already a Unix dependency), so
//! it is portable across every FreeBSD NIC name (vtnet, em, igb, ix, re, ...),
//! VLAN interfaces, and WireGuard, with no device-name assumptions baked in.
//! `mtu` and per-interface statistics are intentionally left for a follow-up:
//! they need extra ioctls / sysctls and are not used by interface selection.

use super::{InterfaceInfo, InterfaceStats};
use anyhow::Result;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;

/// One `InterfaceInfo` per interface, built from `getifaddrs`.
///
/// `getifaddrs` yields one entry per (interface, address-family) tuple, so a
/// VLAN carrying an IPv4, an IPv6, and a link address shows up three times;
/// we fold those into a single record keyed by name. `BTreeMap` keeps the
/// output order deterministic, which the picker relies on when several
/// interfaces are equally good candidates.
pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    let mut by_name: BTreeMap<String, InterfaceInfo> = BTreeMap::new();

    for ifaddr in getifaddrs()? {
        let entry = by_name
            .entry(ifaddr.interface_name.clone())
            .or_insert_with(|| InterfaceInfo {
                name: ifaddr.interface_name.clone(),
                ipv4: None,
                ipv6: None,
                mac: None,
                mtu: None,
                is_up: false,
                is_wireless: None,
                description: None,
            });
        entry.is_up |= ifaddr.flags.contains(InterfaceFlags::IFF_UP);

        let Some(addr) = ifaddr.address else { continue };
        if let Some(sin) = addr.as_sockaddr_in() {
            entry.ipv4.get_or_insert_with(|| sin.ip().to_string());
        } else if let Some(sin6) = addr.as_sockaddr_in6() {
            entry.ipv6.get_or_insert_with(|| sin6.ip().to_string());
        } else if let Some(link) = addr.as_link_addr() {
            if let Some(bytes) = link.addr() {
                if bytes.iter().any(|&b| b != 0) {
                    entry.mac.get_or_insert_with(|| {
                        bytes
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":")
                    });
                }
            }
        }
    }

    // Enrich with kernel interface descriptions (ifdescr). OPNsense sets these
    // to friendly names — "WAN (wan)", "LAN (lan)", "CLIENTS (opt2)" — and
    // libpcap surfaces them as `Device::desc` (the same strings `tcpdump -D`
    // prints), so we get them without parsing OPNsense's config.xml. Portable:
    // on stock FreeBSD with no descriptions set, `desc` is None and this is a
    // no-op, leaving the UI to fall back to its name-based role heuristic.
    if let Ok(devices) = pcap::Device::list() {
        for dev in devices {
            if let (Some(info), Some(desc)) = (by_name.get_mut(&dev.name), dev.desc) {
                let desc = desc.trim();
                if !desc.is_empty() {
                    info.description = Some(desc.to_string());
                }
            }
        }
    }

    Ok(by_name.into_values().collect())
}

/// Name of the interface carrying the IPv4 default route, if the routing
/// table has one. Biases capture selection toward the NIC that actually
/// carries traffic (the WAN on a router) rather than whichever interface the
/// kernel happens to enumerate first. If `route` is missing or the parse
/// fails we return `None` and the picker degrades to "first UP with an IPv4",
/// which is still a valid interface — never `en0`.
pub fn default_route_interface() -> Option<String> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "-inet", "default"])
        .output()
        .ok()?;
    parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
}

/// Pull the `interface:` line out of `route -n get -inet default` output.
fn parse_route_get_interface(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(|v| v.trim().to_string())
    })
}

/// Walk `getifaddrs(3)` once, invoking `f(name, if_data)` for every `AF_LINK`
/// entry. Every interface has exactly one such entry, and it carries the
/// kernel's cumulative counters and negotiated link speed in an `if_data`.
///
/// This centralises the unsafe FFI — and the matching `freeifaddrs` cleanup —
/// so the two public callers below stay safe and don't each hand-roll the walk
/// (the same shape `macos::link_speed_bps` already uses for baudrate). Reading
/// the struct directly avoids forking `netstat -ibn` on every refresh tick,
/// which matters on a router; it also sidesteps FreeBSD's `netstat` column
/// layout differing from macOS's (an extra `Idrop` field).
fn for_each_link_data(mut f: impl FnMut(&str, &nix::libc::if_data)) {
    let mut ifap: *mut nix::libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned list we free below; every
    // pointer is null-checked before it is dereferenced.
    if unsafe { nix::libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_data.is_null() {
            continue;
        }
        // Only the AF_LINK entry carries `if_data`; the AF_INET/INET6 ones
        // point `ifa_data` elsewhere (or nowhere).
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) != nix::libc::AF_LINK {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: on an AF_LINK entry `ifa_data` points to a live `if_data`
        // owned by the list `ifap` still holds.
        let data = unsafe { &*(entry.ifa_data as *const nix::libc::if_data) };
        f(&name, data);
    }
    // SAFETY: `ifap` came from a successful `getifaddrs` and is freed once.
    unsafe { nix::libc::freeifaddrs(ifap) };
}

/// Cumulative per-interface counters from the kernel's `if_data`. Rates are
/// derived upstream (`collectors::traffic`) by diffing successive samples, so
/// this only needs to report the running totals; the caller's `saturating_sub`
/// absorbs the counter reset that happens when an interface bounces.
///
/// `signal_dbm` / `tx_retries` stay `None`: they're 802.11 telemetry, and the
/// wired NICs on a FreeBSD router don't report them through this path.
pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let mut stats = HashMap::new();
    for_each_link_data(|name, d| {
        stats.insert(
            name.to_string(),
            InterfaceStats {
                name: name.to_string(),
                rx_bytes: d.ifi_ibytes,
                tx_bytes: d.ifi_obytes,
                rx_packets: d.ifi_ipackets,
                tx_packets: d.ifi_opackets,
                rx_errors: d.ifi_ierrors,
                tx_errors: d.ifi_oerrors,
                rx_drops: d.ifi_iqdrops,
                tx_drops: d.ifi_oqdrops,
                signal_dbm: None,
                tx_retries: None,
            },
        );
    });
    Ok(stats)
}

/// Negotiated link speed in bits per second from `if_data.ifi_baudrate`, which
/// FreeBSD reports for real NICs (1 Gb on a `vtnet`, the PHY rate on physical
/// Ethernet) and leaves at 0 for interfaces without a meaningful line rate
/// (loopback, some tunnels) — reported here as `None` so the Dense saturation
/// meter labels itself against the observed peak rather than inventing a ceiling.
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    let mut speed = None;
    for_each_link_data(|name, d| {
        if name == iface && d.ifi_baudrate > 0 {
            speed = Some(d.ifi_baudrate);
        }
    });
    speed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_route_get_interface_line() {
        // Shape of `route -n get -inet default` on FreeBSD 15.
        let out = "   route to: default\n\
                   destination: default\n\
                       gateway: 104.182.184.1\n\
                     interface: vtnet1\n\
                         flags: <UP,GATEWAY,DONE,STATIC>\n";
        assert_eq!(parse_route_get_interface(out).as_deref(), Some("vtnet1"));
    }

    #[test]
    fn parse_route_get_interface_none_when_absent() {
        assert_eq!(parse_route_get_interface("no default route\n"), None);
    }

    /// Talks to the live routing table / kernel, so it is environment
    /// dependent and `#[ignore]`d. Run on the target to eyeball what the
    /// enumerator sees: `cargo test --lib freebsd -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_enumeration_smoke() {
        let ifs = collect_interface_info().expect("getifaddrs");
        for i in &ifs {
            println!(
                "{:<8} up={} ipv4={:?} ipv6={:?} mac={:?}",
                i.name, i.is_up, i.ipv4, i.ipv6, i.mac
            );
        }
        assert!(ifs.iter().all(|i| !i.name.is_empty()));
    }
}
