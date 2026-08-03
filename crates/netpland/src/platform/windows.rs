//! Native Windows network adapter discovery.

use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};

use netplan::{AdapterInfo, Capability, CapabilityState, Error, IpAddressInfo, Result};
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIfEntry2,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::{
    IfOperStatusDormant, IfOperStatusDown, IfOperStatusLowerLayerDown, IfOperStatusNotPresent,
    IfOperStatusTesting, IfOperStatusUp,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};

use super::Platform;

pub struct WindowsPlatform;

const HARDWARE_INTERFACE: u8 = 1 << 0;
const FILTER_INTERFACE: u8 = 1 << 1;

impl Platform for WindowsPlatform {
    fn capabilities(&self) -> Vec<Capability> {
        let inventory = enumerate_inventory().unwrap_or_default();
        let has_wifi = inventory.has_wifi;
        vec![
            capability("config.validate", CapabilityState::Available, None),
            capability("config.plan", CapabilityState::Available, None),
            capability(
                "config.apply",
                CapabilityState::DryRun,
                Some("live mutation backends are disabled in 0.1.0"),
            ),
            capability("adapter.inventory", CapabilityState::Available, None),
            capability(
                "adapter.ipv4.apply",
                CapabilityState::DryRun,
                Some("native apply is awaiting protected-interface integration tests"),
            ),
            capability(
                "wifi",
                if has_wifi {
                    CapabilityState::ReadOnly
                } else {
                    CapabilityState::Unavailable
                },
                if has_wifi {
                    Some("WLAN profile mutation is not enabled yet")
                } else {
                    Some("no wireless adapter was discovered")
                },
            ),
            capability(
                "smb",
                CapabilityState::DryRun,
                Some("SMB service and API probes are not enabled yet"),
            ),
        ]
    }

    fn adapters(&self) -> Result<Vec<AdapterInfo>> {
        enumerate_inventory().map(|inventory| inventory.adapters)
    }
}

#[derive(Default)]
struct AdapterInventory {
    adapters: Vec<AdapterInfo>,
    has_wifi: bool,
}

fn capability(name: &str, state: CapabilityState, reason: Option<&str>) -> Capability {
    Capability {
        name: name.into(),
        state,
        reason: reason.map(Into::into),
    }
}

fn enumerate_inventory() -> Result<AdapterInventory> {
    let flags = GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut byte_len = 0_u32;
    // SAFETY: The probe call uses a null output buffer as required by GetAdaptersAddresses,
    // and `byte_len` points to initialized writable storage.
    let probe =
        unsafe { GetAdaptersAddresses(AF_UNSPEC.0.into(), flags, None, None, &raw mut byte_len) };
    if probe != ERROR_BUFFER_OVERFLOW.0 {
        return Err(os_error(probe));
    }
    if byte_len == 0 {
        return Ok(AdapterInventory::default());
    }

    for _ in 0..3 {
        let element_count = (byte_len as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = vec![MaybeUninit::<IP_ADAPTER_ADDRESSES_LH>::uninit(); element_count];
        let pointer = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut actual_len = byte_len;
        // SAFETY: The buffer is aligned for IP_ADAPTER_ADDRESSES_LH and contains at least
        // `byte_len` writable bytes. The API receives the exact allocated byte count.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0.into(),
                flags,
                None,
                Some(pointer),
                &raw mut actual_len,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            byte_len = actual_len;
            continue;
        }
        if result != 0 {
            return Err(os_error(result));
        }
        let base = buffer.as_ptr() as usize;
        let end = base.saturating_add(buffer.len() * size_of::<IP_ADAPTER_ADDRESSES_LH>());
        return collect_adapters(pointer, base, end);
    }
    Err(Error::Io(std::io::Error::other(
        "adapter inventory changed repeatedly while sizing the IP Helper buffer",
    )))
}

fn collect_adapters(
    mut pointer: *mut IP_ADAPTER_ADDRESSES_LH,
    base: usize,
    end: usize,
) -> Result<AdapterInventory> {
    let mut adapters = Vec::new();
    let mut has_wifi = false;
    for _ in 0..4096 {
        if pointer.is_null() {
            return Ok(AdapterInventory { adapters, has_wifi });
        }
        ensure_in_buffer(pointer, base, end)?;
        // SAFETY: `ensure_in_buffer` verified that the full adapter structure is within the
        // initialized API buffer, which remains alive for this entire traversal.
        let adapter = unsafe { &*pointer };
        let next = adapter.Next;
        // SAFETY: GetAdaptersAddresses initializes the documented union member for this OS.
        let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let (hardware, filter) = interface_kind(if_index).unwrap_or({
            (
                matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211),
                false,
            )
        });
        if filter
            || adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK
            || adapter.OperStatus == IfOperStatusNotPresent
        {
            pointer = next;
            continue;
        }
        has_wifi |= adapter.IfType == IF_TYPE_IEEE80211;
        let name =
            wide_string(adapter.FriendlyName).unwrap_or_else(|| format!("ifIndex {if_index}"));
        let description = wide_string(adapter.Description).filter(|value| !value.is_empty());
        let guid = ansi_string(adapter.AdapterName).filter(|value| !value.is_empty());
        let mac_address = format_mac(adapter.PhysicalAddress, adapter.PhysicalAddressLength);
        let (ipv4, ipv6) = collect_unicast(adapter.FirstUnicastAddress, base, end)?;
        adapters.push(AdapterInfo {
            if_index,
            name,
            description,
            guid,
            mac_address,
            status: oper_status(adapter.OperStatus),
            hardware,
            ipv4,
            ipv6,
        });
        pointer = next;
    }
    Err(Error::Protocol(
        "adapter list exceeded the traversal limit".into(),
    ))
}

fn interface_kind(if_index: u32) -> Option<(bool, bool)> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: if_index,
        ..Default::default()
    };
    // SAFETY: `row` points to fully initialized writable storage and identifies the interface by
    // index as required by GetIfEntry2. Windows initializes the remaining fields on success.
    let result = unsafe { GetIfEntry2(&raw mut row) };
    if result.0 != 0 {
        return None;
    }
    let flags = row.InterfaceAndOperStatusFlags._bitfield;
    Some((
        flags & HARDWARE_INTERFACE != 0,
        flags & FILTER_INTERFACE != 0,
    ))
}

#[allow(clippy::cast_ptr_alignment)]
fn collect_unicast(
    mut pointer: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
    base: usize,
    end: usize,
) -> Result<(Vec<IpAddressInfo>, Vec<IpAddressInfo>)> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for _ in 0..4096 {
        if pointer.is_null() {
            return Ok((ipv4, ipv6));
        }
        ensure_in_buffer(pointer, base, end)?;
        // SAFETY: The complete unicast structure was bounds-checked against the live API buffer.
        let unicast = unsafe { &*pointer };
        let socket = unicast.Address.lpSockaddr;
        if !socket.is_null() {
            // SAFETY: Windows guarantees lpSockaddr points to at least a SOCKADDR within the
            // GetAdaptersAddresses buffer. The family determines the concrete structure.
            let family = unsafe { (*socket).sa_family };
            if family == AF_INET {
                let address = socket.cast::<SOCKADDR_IN>();
                ensure_in_buffer(address, base, end)?;
                // SAFETY: Family AF_INET and the bounds check establish a complete SOCKADDR_IN.
                // `read_unaligned` avoids imposing Rust's stronger alignment on the API pointer.
                let address = unsafe { address.read_unaligned() };
                // SAFETY: The IPv4 union member is initialized for an AF_INET address.
                let bytes = unsafe { address.sin_addr.S_un.S_un_b };
                ipv4.push(IpAddressInfo {
                    address: Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4)
                        .to_string(),
                    prefix_length: unicast.OnLinkPrefixLength,
                });
            } else if family == AF_INET6 {
                let address = socket.cast::<SOCKADDR_IN6>();
                ensure_in_buffer(address, base, end)?;
                // SAFETY: Family AF_INET6 and the bounds check establish a complete SOCKADDR_IN6.
                // `read_unaligned` avoids imposing Rust's stronger alignment on the API pointer.
                let address = unsafe { address.read_unaligned() };
                // SAFETY: The IPv6 union byte member is initialized for an AF_INET6 address.
                let bytes = unsafe { address.sin6_addr.u.Byte };
                ipv6.push(IpAddressInfo {
                    address: Ipv6Addr::from(bytes).to_string(),
                    prefix_length: unicast.OnLinkPrefixLength,
                });
            }
        }
        pointer = unicast.Next;
    }
    Err(Error::Protocol(
        "unicast address list exceeded the traversal limit".into(),
    ))
}

fn ensure_in_buffer<T>(pointer: *const T, base: usize, end: usize) -> Result<()> {
    let start = pointer as usize;
    if start < base
        || start
            .checked_add(size_of::<T>())
            .is_none_or(|value| value > end)
    {
        return Err(Error::Protocol(
            "Windows IP Helper returned an out-of-bounds pointer".into(),
        ));
    }
    Ok(())
}

fn wide_string(value: windows::core::PWSTR) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: The pointer comes from a successful GetAdaptersAddresses buffer and is documented
    // as a NUL-terminated UTF-16 string valid for the lifetime of that buffer.
    unsafe { value.to_string().ok() }
}

fn ansi_string(value: windows::core::PSTR) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: The pointer comes from a successful GetAdaptersAddresses buffer and is documented
    // as a NUL-terminated adapter name valid for the lifetime of that buffer.
    unsafe { value.to_string().ok() }
}

fn format_mac(bytes: [u8; 8], length: u32) -> Option<String> {
    let length = usize::try_from(length).ok()?.min(bytes.len());
    if length == 0 {
        return None;
    }
    Some(
        bytes[..length]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join("-"),
    )
}

fn oper_status(status: windows::Win32::NetworkManagement::Ndis::IF_OPER_STATUS) -> String {
    if status == IfOperStatusUp {
        "up"
    } else if status == IfOperStatusDown {
        "down"
    } else if status == IfOperStatusTesting {
        "testing"
    } else if status == IfOperStatusDormant {
        "dormant"
    } else if status == IfOperStatusNotPresent {
        "not_present"
    } else if status == IfOperStatusLowerLayerDown {
        "lower_layer_down"
    } else {
        "unknown"
    }
    .into()
}

fn os_error(code: u32) -> Error {
    let raw = i32::try_from(code).unwrap_or(i32::MAX);
    Error::Io(std::io::Error::from_raw_os_error(raw))
}
