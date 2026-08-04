//! Native Windows network adapter discovery.

mod apply;
mod smb;
mod wifi;

use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use netplan::config::{DriverOperation, InterfaceSelector, WifiAction};
use netplan::{
    AdapterInfo, Capability, CapabilityState, Error, IpAddressInfo, NetplanConfig, Result,
    WifiInterfaceStatus, WifiNetwork,
};
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIfEntry2,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_DHCP_ENABLED, IP_ADAPTER_DNS_SERVER_ADDRESS_XP, IP_ADAPTER_GATEWAY_ADDRESS_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, IP_ADAPTER_WINS_SERVER_ADDRESS_LH, MIB_IF_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::{
    IfOperStatusDormant, IfOperStatusDown, IfOperStatusLowerLayerDown, IfOperStatusNotPresent,
    IfOperStatusTesting, IfOperStatusUp, NET_IF_ADMIN_STATUS_UP,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IpPrefixOriginManual, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

use super::{ApplyReport, Platform, PlatformError, PlatformResult, require_plan_capabilities};

pub struct WindowsPlatform;

const HARDWARE_INTERFACE: u8 = 1 << 0;
const FILTER_INTERFACE: u8 = 1 << 1;

impl Platform for WindowsPlatform {
    #[allow(clippy::too_many_lines)]
    fn capabilities(&self) -> Vec<Capability> {
        let has_netsh = apply::netsh_available();
        let has_pnputil = apply::pnputil_available();
        let mut capabilities = vec![
            capability("config.validate", CapabilityState::Available, None),
            capability("config.plan", CapabilityState::Available, None),
            capability("config.apply", CapabilityState::Available, None),
            capability("adapter.inventory", CapabilityState::Available, None),
            capability(
                "adapter.ipv4.apply",
                if has_netsh {
                    CapabilityState::Available
                } else {
                    CapabilityState::Unavailable
                },
                (!has_netsh).then_some("netsh.exe is unavailable in this image"),
            ),
        ];
        capabilities.push(capability(
            "adapter.state.apply",
            if has_netsh {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            (!has_netsh).then_some("netsh.exe is unavailable in this image"),
        ));
        capabilities.push(capability(
            "adapter.mac.apply",
            if has_netsh {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            (!has_netsh).then_some("netsh.exe is unavailable for adapter restart"),
        ));
        capabilities.push(capability(
            "adapter.restart",
            if has_netsh {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            (!has_netsh).then_some("netsh.exe is unavailable in this image"),
        ));
        capabilities.push(capability(
            "firewall.apply",
            if has_netsh {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            (!has_netsh).then_some("netsh.exe is unavailable in this image"),
        ));
        capabilities.extend(
            [
                "identity.computer_name.apply",
                "identity.workgroup.apply",
                "identity.dns_suffix.apply",
            ]
            .map(|name| capability(name, CapabilityState::Available, None)),
        );
        capabilities.push(capability(
            "service.apply",
            CapabilityState::Available,
            None,
        ));
        capabilities.push(capability("hook.execute", CapabilityState::Available, None));
        capabilities.push(capability(
            "driver.install",
            if has_pnputil {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            (!has_pnputil).then_some("pnputil.exe is unavailable in this image"),
        ));
        let has_force_driver = apply::force_driver_available();
        capabilities.push(capability(
            "driver.force_install",
            if has_force_driver {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            (!has_force_driver)
                .then_some("newdev.dll force-install backend is unavailable in this image"),
        ));
        let wifi_probe = wifi::probe();
        for name in [
            "wifi.status",
            "wifi.profile.apply",
            "wifi.scan",
            "wifi.connect",
            "wifi.disconnect",
        ] {
            let wifi_available = wifi_probe.is_ok();
            let reason = match &wifi_probe {
                Ok(()) => None,
                Err(reason) => Some(reason.as_str()),
            };
            capabilities.push(capability(
                name,
                if wifi_available {
                    CapabilityState::Available
                } else {
                    CapabilityState::Unavailable
                },
                reason,
            ));
        }
        let account_probe = smb::probe_accounts();
        capabilities.push(capability(
            "smb.account.apply",
            if account_probe.is_ok() {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            account_probe.as_ref().err().map(String::as_str),
        ));
        let share_probe = smb::probe_shares();
        capabilities.push(capability(
            "smb.share.apply",
            if share_probe.is_ok() {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            share_probe.as_ref().err().map(String::as_str),
        ));
        let mapping_probe = smb::probe_mappings();
        capabilities.push(capability(
            "smb.mapping.apply",
            if mapping_probe.is_ok() {
                CapabilityState::Available
            } else {
                CapabilityState::Unavailable
            },
            mapping_probe.as_ref().err().map(String::as_str),
        ));
        capabilities
    }

    fn adapters(&self) -> Result<Vec<AdapterInfo>> {
        enumerate_inventory().map(|inventory| {
            inventory
                .adapters
                .into_iter()
                .map(|adapter| adapter.info)
                .collect()
        })
    }

    fn wifi_status(&self, if_index: Option<u32>) -> PlatformResult<Vec<WifiInterfaceStatus>> {
        let inventory = enumerate_inventory().map_err(|error| {
            PlatformError::internal(format!("Wi-Fi status inventory failed: {error}"))
        })?;
        let client = wifi::Client::open()?;
        let interfaces = client.interfaces()?;
        select_wifi_interfaces(&interfaces, if_index)?
            .into_iter()
            .map(|interface| {
                let adapter = inventory
                    .adapters
                    .iter()
                    .find(|adapter| adapter.info.if_index == interface.if_index);
                let name = adapter
                    .map(|adapter| adapter.info.name.as_str())
                    .filter(|name| !name.is_empty())
                    .unwrap_or(&interface.description);
                client.interface_status(
                    &interface.guid,
                    interface.state,
                    interface.if_index,
                    name,
                    adapter.and_then(|adapter| adapter.info.guid.clone()),
                )
            })
            .collect()
    }

    fn wifi_scan(
        &self,
        if_index: Option<u32>,
        refresh: bool,
        timeout: Duration,
    ) -> PlatformResult<(bool, Vec<WifiNetwork>)> {
        let inventory = enumerate_inventory().map_err(|error| {
            PlatformError::internal(format!("Wi-Fi scan inventory failed: {error}"))
        })?;
        let client = wifi::Client::open()?;
        let interfaces = client.interfaces()?;
        let selected = select_wifi_interfaces(&interfaces, if_index)?;
        let mut scannable = Vec::with_capacity(selected.len());
        let mut radio_off = Vec::new();
        for interface in selected {
            if client.radio_state(&interface.guid)? == wifi::RadioState::Off {
                radio_off.push(interface.if_index);
            } else {
                scannable.push(interface);
            }
        }
        if scannable.is_empty() {
            let indexes = radio_off
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(PlatformError::unsupported(format!(
                "Wi-Fi radio is off for Native Wi-Fi interface if_index={indexes}; turn on Wi-Fi and retry"
            )));
        }
        let mut refreshed = refresh && radio_off.is_empty();
        let mut networks = Vec::new();
        for interface in scannable {
            let name = inventory
                .adapters
                .iter()
                .find(|adapter| adapter.info.if_index == interface.if_index)
                .map(|adapter| adapter.info.name.as_str())
                .filter(|name| !name.is_empty())
                .unwrap_or(&interface.description);
            if refresh {
                refreshed &= client.scan_and_wait(&interface.guid, timeout)?;
            }
            networks.extend(client.available_networks(
                &interface.guid,
                interface.if_index,
                name,
            )?);
        }
        networks.sort_by(|left, right| {
            right
                .connected
                .cmp(&left.connected)
                .then_with(|| right.signal_quality.cmp(&left.signal_quality))
                .then_with(|| left.ssid.cmp(&right.ssid))
                .then_with(|| left.interface_if_index.cmp(&right.interface_if_index))
        });
        Ok((refreshed, networks))
    }

    fn preflight(&self, config: &NetplanConfig) -> PlatformResult<()> {
        require_plan_capabilities(&self.capabilities(), config)?;
        let inventory = enumerate_inventory().map_err(|error| {
            PlatformError::internal(format!("adapter preflight inventory failed: {error}"))
        })?;
        let interfaces = if config.wifi.is_empty() && config.wifi_actions.is_empty() {
            Vec::new()
        } else {
            wifi::Client::open()?.interfaces()?
        };
        validate_runtime_protection(config, &inventory, &interfaces)
    }

    fn apply(&self, config: &NetplanConfig) -> PlatformResult<ApplyReport> {
        apply::apply(config)
    }
}

fn select_wifi_interfaces(
    interfaces: &[wifi::Interface],
    if_index: Option<u32>,
) -> PlatformResult<Vec<&wifi::Interface>> {
    if let Some(if_index) = if_index {
        let interface = interfaces
            .iter()
            .find(|interface| interface.if_index == if_index)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "no enabled Native Wi-Fi interface exists with if_index={if_index}"
                ))
            })?;
        return Ok(vec![interface]);
    }
    if interfaces.is_empty() {
        Err(PlatformError::not_found(
            "no enabled Native Wi-Fi interface is available",
        ))
    } else {
        Ok(interfaces.iter().collect())
    }
}

fn validate_runtime_protection(
    config: &NetplanConfig,
    inventory: &AdapterInventory,
    wifi_interfaces: &[wifi::Interface],
) -> PlatformResult<()> {
    let protected: Vec<u32> = config
        .protect
        .management_interfaces
        .iter()
        .map(|selector| resolve_adapter(inventory, selector).map(|adapter| adapter.info.if_index))
        .collect::<PlatformResult<_>>()?;
    let mut targets = Vec::new();
    for adapter in &config.adapters {
        let if_index = resolve_adapter(inventory, &adapter.selector)?.info.if_index;
        if targets.contains(&if_index) {
            return Err(PlatformError::invalid_config(format!(
                "multiple adapter entries resolve to if_index={if_index}"
            )));
        }
        targets.push(if_index);
    }
    for profile in &config.wifi {
        targets.push(
            resolve_wifi_interface(inventory, wifi_interfaces, profile.selector.as_ref())?.if_index,
        );
    }
    for action in &config.wifi_actions {
        let selector = match action {
            WifiAction::Scan { selector }
            | WifiAction::Connect { selector, .. }
            | WifiAction::Disconnect { selector } => selector.as_ref(),
        };
        targets.push(resolve_wifi_interface(inventory, wifi_interfaces, selector)?.if_index);
    }
    for operation in &config.drivers {
        if let DriverOperation::RestartAdapter { selector } = operation {
            targets.push(resolve_adapter(inventory, selector)?.info.if_index);
        }
    }
    if let Some(if_index) = targets
        .into_iter()
        .find(|target| protected.contains(target))
    {
        return Err(PlatformError::invalid_config(format!(
            "live configuration resolves to protected management interface if_index={if_index}"
        )));
    }
    Ok(())
}

fn resolve_wifi_interface<'a>(
    inventory: &AdapterInventory,
    interfaces: &'a [wifi::Interface],
    selector: Option<&InterfaceSelector>,
) -> PlatformResult<&'a wifi::Interface> {
    if let Some(selector) = selector {
        let adapter = resolve_adapter(inventory, selector)?;
        interfaces
            .iter()
            .find(|interface| interface.if_index == adapter.info.if_index)
            .ok_or_else(|| {
                PlatformError::invalid_config(format!(
                    "selector resolves to interface if_index={}, which is not exposed by Native Wi-Fi",
                    adapter.info.if_index
                ))
            })
    } else {
        let mut matches = interfaces.iter();
        let Some(first) = matches.next() else {
            return Err(PlatformError::not_found(
                "no enabled Native Wi-Fi interface is available",
            ));
        };
        if matches.next().is_some() {
            return Err(PlatformError::invalid_config(
                "multiple Native Wi-Fi interfaces are available; an explicit selector is required",
            ));
        }
        Ok(first)
    }
}

fn resolve_adapter<'a>(
    inventory: &'a AdapterInventory,
    selector: &InterfaceSelector,
) -> PlatformResult<&'a AdapterSnapshot> {
    let matches: Vec<_> = inventory
        .adapters
        .iter()
        .filter(|adapter| selector_matches(selector, &adapter.info))
        .collect();
    match matches.as_slice() {
        [adapter] => Ok(adapter),
        [] => Err(PlatformError::not_found(format!(
            "interface selector did not match any adapter: {selector:?}"
        ))),
        _ => Err(PlatformError::invalid_config(format!(
            "interface selector is ambiguous and matched {} adapters: {selector:?}",
            matches.len()
        ))),
    }
}

fn selector_matches(selector: &InterfaceSelector, adapter: &AdapterInfo) -> bool {
    selector
        .if_index
        .is_none_or(|value| value == adapter.if_index)
        && selector
            .name
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case(&adapter.name))
        && selector.guid.as_deref().is_none_or(|value| {
            adapter.guid.as_deref().is_some_and(|candidate| {
                value
                    .trim_matches(['{', '}'])
                    .eq_ignore_ascii_case(candidate.trim_matches(['{', '}']))
            })
        })
        && selector.mac_address.as_deref().is_none_or(|value| {
            adapter
                .mac_address
                .as_deref()
                .is_some_and(|candidate| canonical_mac(value) == canonical_mac(candidate))
        })
        && selector
            .description_contains
            .as_deref()
            .is_none_or(|value| {
                adapter.description.as_deref().is_some_and(|description| {
                    description.to_lowercase().contains(&value.to_lowercase())
                })
            })
}

fn canonical_mac(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '-' && *character != ':')
        .flat_map(char::to_uppercase)
        .collect()
}

#[derive(Default)]
struct AdapterInventory {
    adapters: Vec<AdapterSnapshot>,
}

#[derive(Clone, Debug)]
struct AdapterSnapshot {
    info: AdapterInfo,
    admin_enabled: bool,
    dhcp_enabled: bool,
    manual_ipv4: Vec<IpAddressInfo>,
    gateways: Vec<Ipv4Addr>,
    dns: Vec<IpAddr>,
    wins: Vec<Ipv4Addr>,
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
        | GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST;
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
    for _ in 0..4096 {
        if pointer.is_null() {
            return Ok(AdapterInventory { adapters });
        }
        ensure_in_buffer(pointer, base, end)?;
        // SAFETY: `ensure_in_buffer` verified that the full adapter structure is within the
        // initialized API buffer, which remains alive for this entire traversal.
        let adapter = unsafe { &*pointer };
        let next = adapter.Next;
        // SAFETY: GetAdaptersAddresses initializes the documented union member for this OS.
        let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let details = interface_details(if_index).unwrap_or(InterfaceDetails {
            hardware: matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211),
            filter: false,
            admin_enabled: adapter.OperStatus != IfOperStatusNotPresent,
        });
        if details.filter
            || adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK
            || adapter.OperStatus == IfOperStatusNotPresent
        {
            pointer = next;
            continue;
        }
        let name =
            wide_string(adapter.FriendlyName).unwrap_or_else(|| format!("ifIndex {if_index}"));
        let description = wide_string(adapter.Description).filter(|value| !value.is_empty());
        let guid = ansi_string(adapter.AdapterName).filter(|value| !value.is_empty());
        let mac_address = format_mac(adapter.PhysicalAddress, adapter.PhysicalAddressLength);
        let (ipv4, ipv6, manual_ipv4) = collect_unicast(adapter.FirstUnicastAddress, base, end)?;
        let gateways = collect_gateways(adapter.FirstGatewayAddress, base, end)?;
        let dns = collect_dns(adapter.FirstDnsServerAddress, base, end)?;
        let wins = collect_wins(adapter.FirstWinsServerAddress, base, end)?;
        // SAFETY: GetAdaptersAddresses initializes the flags union member on supported systems.
        let flags = unsafe { adapter.Anonymous2.Flags };
        let info = AdapterInfo {
            if_index,
            name,
            description,
            guid,
            mac_address,
            status: oper_status(adapter.OperStatus),
            hardware: details.hardware,
            ipv4,
            ipv6,
        };
        adapters.push(AdapterSnapshot {
            info,
            admin_enabled: details.admin_enabled,
            dhcp_enabled: flags & IP_ADAPTER_DHCP_ENABLED != 0,
            manual_ipv4,
            gateways,
            dns,
            wins,
        });
        pointer = next;
    }
    Err(Error::Protocol(
        "adapter list exceeded the traversal limit".into(),
    ))
}

struct InterfaceDetails {
    hardware: bool,
    filter: bool,
    admin_enabled: bool,
}

fn interface_details(if_index: u32) -> Option<InterfaceDetails> {
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
    Some(InterfaceDetails {
        hardware: flags & HARDWARE_INTERFACE != 0,
        filter: flags & FILTER_INTERFACE != 0,
        admin_enabled: row.AdminStatus == NET_IF_ADMIN_STATUS_UP,
    })
}

#[allow(clippy::cast_ptr_alignment)]
fn collect_unicast(
    mut pointer: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
    base: usize,
    end: usize,
) -> Result<(Vec<IpAddressInfo>, Vec<IpAddressInfo>, Vec<IpAddressInfo>)> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut manual_ipv4 = Vec::new();
    for _ in 0..4096 {
        if pointer.is_null() {
            return Ok((ipv4, ipv6, manual_ipv4));
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
                let info = IpAddressInfo {
                    address: Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4)
                        .to_string(),
                    prefix_length: unicast.OnLinkPrefixLength,
                };
                if unicast.PrefixOrigin == IpPrefixOriginManual {
                    manual_ipv4.push(info.clone());
                }
                ipv4.push(info);
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

fn collect_gateways(
    mut pointer: *mut IP_ADAPTER_GATEWAY_ADDRESS_LH,
    base: usize,
    end: usize,
) -> Result<Vec<Ipv4Addr>> {
    let mut values = Vec::new();
    for _ in 0..4096 {
        if pointer.is_null() {
            return Ok(values);
        }
        ensure_in_buffer(pointer, base, end)?;
        // SAFETY: The complete gateway structure was bounds-checked against the API buffer.
        let item = unsafe { &*pointer };
        if let Some(IpAddr::V4(address)) = socket_address(&item.Address, base, end)? {
            values.push(address);
        }
        pointer = item.Next;
    }
    Err(Error::Protocol(
        "gateway address list exceeded the traversal limit".into(),
    ))
}

fn collect_dns(
    mut pointer: *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    base: usize,
    end: usize,
) -> Result<Vec<IpAddr>> {
    let mut values = Vec::new();
    for _ in 0..4096 {
        if pointer.is_null() {
            return Ok(values);
        }
        ensure_in_buffer(pointer, base, end)?;
        // SAFETY: The complete DNS structure was bounds-checked against the API buffer.
        let item = unsafe { &*pointer };
        if let Some(address) = socket_address(&item.Address, base, end)? {
            values.push(address);
        }
        pointer = item.Next;
    }
    Err(Error::Protocol(
        "DNS server list exceeded the traversal limit".into(),
    ))
}

fn collect_wins(
    mut pointer: *mut IP_ADAPTER_WINS_SERVER_ADDRESS_LH,
    base: usize,
    end: usize,
) -> Result<Vec<Ipv4Addr>> {
    let mut values = Vec::new();
    for _ in 0..4096 {
        if pointer.is_null() {
            return Ok(values);
        }
        ensure_in_buffer(pointer, base, end)?;
        // SAFETY: The complete WINS structure was bounds-checked against the API buffer.
        let item = unsafe { &*pointer };
        if let Some(IpAddr::V4(address)) = socket_address(&item.Address, base, end)? {
            values.push(address);
        }
        pointer = item.Next;
    }
    Err(Error::Protocol(
        "WINS server list exceeded the traversal limit".into(),
    ))
}

#[allow(clippy::cast_ptr_alignment)]
fn socket_address(address: &SOCKET_ADDRESS, base: usize, end: usize) -> Result<Option<IpAddr>> {
    let socket = address.lpSockaddr;
    if socket.is_null() {
        return Ok(None);
    }
    ensure_in_buffer(socket, base, end)?;
    // SAFETY: The base socket structure is within the live GetAdaptersAddresses buffer.
    let family = unsafe { (*socket).sa_family };
    if family == AF_INET {
        let address = socket.cast::<SOCKADDR_IN>();
        ensure_in_buffer(address, base, end)?;
        // SAFETY: AF_INET and the bounds check establish a complete SOCKADDR_IN.
        let address = unsafe { address.read_unaligned() };
        // SAFETY: The IPv4 union byte member is initialized for AF_INET.
        let bytes = unsafe { address.sin_addr.S_un.S_un_b };
        Ok(Some(IpAddr::V4(Ipv4Addr::new(
            bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
        ))))
    } else if family == AF_INET6 {
        let address = socket.cast::<SOCKADDR_IN6>();
        ensure_in_buffer(address, base, end)?;
        // SAFETY: AF_INET6 and the bounds check establish a complete SOCKADDR_IN6.
        let address = unsafe { address.read_unaligned() };
        // SAFETY: The IPv6 union byte member is initialized for AF_INET6.
        let bytes = unsafe { address.sin6_addr.u.Byte };
        Ok(Some(IpAddr::V6(Ipv6Addr::from(bytes))))
    } else {
        Ok(None)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PlatformErrorKind;
    use windows::Win32::NetworkManagement::WiFi::wlan_interface_state_disconnected;
    use windows::core::GUID;

    fn native_interface(if_index: u32) -> wifi::Interface {
        wifi::Interface {
            guid: GUID::from_u128(u128::from(if_index)),
            if_index,
            description: format!("Wi-Fi {if_index}"),
            state: wlan_interface_state_disconnected,
        }
    }

    #[test]
    fn wifi_scan_without_selector_targets_every_native_interface() {
        let interfaces = [native_interface(7), native_interface(12)];

        let Ok(selected) = select_wifi_interfaces(&interfaces, None) else {
            panic!("all native interfaces should be selected");
        };

        assert_eq!(
            selected
                .iter()
                .map(|interface| interface.if_index)
                .collect::<Vec<_>>(),
            vec![7, 12]
        );
    }

    #[test]
    fn wifi_scan_if_index_targets_one_exact_native_interface() {
        let interfaces = [native_interface(7), native_interface(12)];

        let Ok(selected) = select_wifi_interfaces(&interfaces, Some(12)) else {
            panic!("the requested native interface should be selected");
        };

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].if_index, 12);
    }

    #[test]
    fn wifi_scan_rejects_an_index_outside_native_wifi_inventory() {
        let interfaces = [native_interface(7)];

        let Err(error) = select_wifi_interfaces(&interfaces, Some(99)) else {
            panic!("a non-native interface index should be rejected");
        };

        assert_eq!(error.kind, PlatformErrorKind::NotFound);
        assert!(error.message.contains("if_index=99"));
    }
}
