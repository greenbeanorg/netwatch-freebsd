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

use super::InterfaceInfo;
use anyhow::Result;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use std::collections::BTreeMap;

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
