//! `GetAdaptersAddresses` from iphlpapi, declared by hand like the kernel32
//! calls in `platform::npcap` rather than taking a Windows API crate for one
//! function.

use super::InterfaceInfo;
use std::ffi::{c_char, c_void};
use std::net::{Ipv4Addr, Ipv6Addr};

const AF_UNSPEC: u32 = 0;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
const GAA_FLAG_SKIP_ANYCAST: u32 = 0x2;
const GAA_FLAG_SKIP_MULTICAST: u32 = 0x4;
const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x8;
const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_NO_DATA: u32 = 232;
const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_IEEE80211: u32 = 71;
const IF_OPER_STATUS_UP: i32 = 1;

#[repr(C)]
struct SocketAddress {
    sockaddr: *const u8,
    length: i32,
}

/// `IP_ADAPTER_UNICAST_ADDRESS_LH`, up to the address. Only ever read through
/// pointers the API hands back, so the tail can stay undeclared.
#[repr(C)]
struct UnicastAddress {
    alignment: u64, // union { Alignment; { Length; Flags } }
    next: *const UnicastAddress,
    address: SocketAddress,
}

/// `IP_ADAPTER_ADDRESSES_LH`, up to `OperStatus` — a prefix unchanged since
/// Windows XP. The API allocates the records and chains them through `next`,
/// so declaring the prefix is enough to walk the list.
#[repr(C)]
struct AdapterAddresses {
    alignment: u64, // union { Alignment; { Length; IfIndex } }
    next: *const AdapterAddresses,
    adapter_name: *const c_char,
    first_unicast: *const UnicastAddress,
    first_anycast: *const c_void,
    first_multicast: *const c_void,
    first_dns_server: *const c_void,
    dns_suffix: *const u16,
    description: *const u16,
    friendly_name: *const u16,
    physical_address: [u8; 8],
    physical_address_length: u32,
    flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: i32,
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *mut c_void,
        addresses: *mut AdapterAddresses,
        size: *mut u32,
    ) -> u32;
}

/// Every adapter with an IP stack bound, loopback excluded — the set ipconfig
/// listed. `Err` carries the Win32 error code.
pub fn adapters() -> Result<Vec<InterfaceInfo>, u32> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // Microsoft's suggested starting size; the call reports the size it needs
    // if adapters appeared in between, so retry a few times.
    let mut size: u32 = 15_000;
    for _ in 0..4 {
        // u64 elements keep the buffer 8-byte aligned for the records.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        // Safety: `buf` is at least `size` bytes, writable and aligned for
        // the records the API places in it.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match rc {
            // Safety: on success the buffer holds a valid list, and it lives
            // until `walk` returns.
            ERROR_SUCCESS => return Ok(unsafe { walk(buf.as_ptr().cast()) }),
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW => continue,
            other => return Err(other),
        }
    }
    Err(ERROR_BUFFER_OVERFLOW)
}

/// Safety: `first` is the head of a list `GetAdaptersAddresses` filled in, and
/// the buffer holding it outlives the call.
unsafe fn walk(first: *const AdapterAddresses) -> Vec<InterfaceInfo> {
    let mut out = Vec::new();
    let mut cur = first;
    while let Some(a) = cur.as_ref() {
        cur = a.next;
        if a.if_type == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let name = wide_to_string(a.friendly_name);
        if name.is_empty() {
            continue;
        }
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut ua = a.first_unicast;
        while let Some(u) = ua.as_ref() {
            ua = u.next;
            match sockaddr_ip(u.address.sockaddr, u.address.length) {
                Some(Ip::V4(ip)) => v4.push(ip),
                Some(Ip::V6(ip)) => v6.push(ip),
                None => {}
            }
        }
        let is_up = a.oper_status == IF_OPER_STATUS_UP;
        // A disconnected adapter keeps a stale or 169.254 autoconfig address
        // the API still reports; ipconfig showed none, and the address is a
        // capture-matching fallback, so report it only while the link is up.
        if !is_up {
            v4.clear();
            v6.clear();
        }
        let mac_len = (a.physical_address_length as usize).min(a.physical_address.len());
        out.push(InterfaceInfo {
            name,
            ipv4: v4.first().map(|ip| ip.to_string()),
            ipv6: pick_ipv6(&v6).map(|ip| ip.to_string()),
            mac: format_mac(&a.physical_address[..mac_len]),
            mtu: (a.mtu != 0 && a.mtu != u32::MAX).then_some(a.mtu),
            is_up,
            is_wireless: wireless_from_if_type(a.if_type),
        });
    }
    out
}

/// Safety: `p` is null or points at a NUL-terminated UTF-16 string.
unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

enum Ip {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// `sockaddr_in` keeps the address at byte 4, `sockaddr_in6` at byte 8.
///
/// Safety: `sa` is null or points at `len` readable bytes.
unsafe fn sockaddr_ip(sa: *const u8, len: i32) -> Option<Ip> {
    if sa.is_null() || len < 2 {
        return None;
    }
    let raw = std::slice::from_raw_parts(sa, len as usize);
    match u16::from_ne_bytes([raw[0], raw[1]]) {
        AF_INET if raw.len() >= 8 => {
            let b: [u8; 4] = raw[4..8].try_into().ok()?;
            Some(Ip::V4(Ipv4Addr::from(b)))
        }
        AF_INET6 if raw.len() >= 24 => {
            let b: [u8; 16] = raw[8..24].try_into().ok()?;
            Some(Ip::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// The preference ipconfig's ordering gave the old parser: a routable address
/// over the link-local one every adapter carries.
fn pick_ipv6(addrs: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    let link_local = |ip: &Ipv6Addr| (ip.segments()[0] & 0xffc0) == 0xfe80;
    addrs
        .iter()
        .find(|ip| !link_local(ip))
        .or_else(|| addrs.first())
        .copied()
}

/// `AA:BB:CC:DD:EE:FF`, the form the ipconfig parser produced.
fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.iter().all(|b| *b == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Wi-Fi is IEEE 802.11 and wired is Ethernet CSMA/CD; tunnels, VPNs and the
/// rest stay unknown, as `InterfaceInfo::is_wireless` documents.
fn wireless_from_if_type(if_type: u32) -> Option<bool> {
    match if_type {
        IF_TYPE_IEEE80211 => Some(true),
        IF_TYPE_ETHERNET_CSMACD => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_routable_ipv6_over_link_local() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::5".parse().unwrap();
        assert_eq!(pick_ipv6(&[ll, global]), Some(global));
        assert_eq!(pick_ipv6(&[ll]), Some(ll));
        assert_eq!(pick_ipv6(&[]), None);
    }

    #[test]
    fn formats_mac_like_ipconfig_did() {
        assert_eq!(
            format_mac(&[0x00, 0x15, 0x5d, 0x5b, 0x96, 0x1c]).as_deref(),
            Some("00:15:5D:5B:96:1C")
        );
        assert_eq!(format_mac(&[]), None);
        assert_eq!(format_mac(&[0; 6]), None);
    }

    #[test]
    fn wireless_only_from_known_media() {
        assert_eq!(wireless_from_if_type(IF_TYPE_IEEE80211), Some(true));
        assert_eq!(wireless_from_if_type(IF_TYPE_ETHERNET_CSMACD), Some(false));
        assert_eq!(wireless_from_if_type(53), None); // IF_TYPE_PROP_VIRTUAL
    }

    #[test]
    fn decodes_sockaddr_in_and_in6() {
        let mut v4 = [0u8; 16];
        v4[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        v4[4..8].copy_from_slice(&[192, 168, 2, 109]);
        match unsafe { sockaddr_ip(v4.as_ptr(), 16) } {
            Some(Ip::V4(ip)) => assert_eq!(ip, Ipv4Addr::new(192, 168, 2, 109)),
            _ => panic!("expected IPv4"),
        }

        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut v6 = [0u8; 28];
        v6[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        v6[8..24].copy_from_slice(&ll.octets());
        match unsafe { sockaddr_ip(v6.as_ptr(), 28) } {
            Some(Ip::V6(ip)) => assert_eq!(ip, ll),
            _ => panic!("expected IPv6"),
        }

        assert!(unsafe { sockaddr_ip(std::ptr::null(), 16) }.is_none());
    }

    /// Against the machine's real adapters: every name must be one the
    /// Get-NetAdapter lookups can key on — non-empty, and free of the
    /// replacement character a code-page mismatch leaves behind.
    #[test]
    fn live_adapter_names_are_clean_unicode() {
        let adapters = adapters().expect("GetAdaptersAddresses");
        for a in &adapters {
            assert!(!a.name.is_empty());
            assert!(!a.name.contains('\u{FFFD}'), "mangled name {:?}", a.name);
        }
    }
}
