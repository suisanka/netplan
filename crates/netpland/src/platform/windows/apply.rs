//! Transactional Windows backends for machine identity, services, and hooks.

use std::ffi::c_void;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use netplan::NetplanConfig;
use netplan::config::{
    DriverOperation, HookConfig, HookStage, Ipv4Config, RestartPolicy, ServiceState, WifiAction,
};
use windows::Win32::NetworkManagement::NetManagement::{
    NET_JOIN_DOMAIN_JOIN_OPTIONS, NETSETUP_JOIN_STATUS, NetApiBufferFree, NetGetJoinInformation,
    NetJoinDomain, NetSetupWorkgroupName,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_ROUTINE_FLAGS, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_MULTI_SZ,
    RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, StartServiceW,
};
use windows::Win32::System::SystemInformation::{
    COMPUTER_NAME_FORMAT, ComputerNamePhysicalDnsDomain, ComputerNamePhysicalDnsHostname,
    GetComputerNameExW, SetComputerNameExW,
};
use windows::core::{BOOL, PCSTR, PCWSTR, PWSTR};

use super::super::{ApplyReport, PlatformError, PlatformResult};
use super::{
    AdapterSnapshot, canonical_mac, enumerate_inventory, resolve_adapter, resolve_wifi_interface,
    smb, wifi,
};

const SERVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn apply(config: &NetplanConfig) -> PlatformResult<ApplyReport> {
    let mut rollback = Vec::new();
    run_hooks(config, HookStage::BeforeApply)?;
    let mut irreversible_change = false;
    let mut result = apply_reversible(config, &mut rollback);
    if result.is_ok() {
        irreversible_change = config
            .drivers
            .iter()
            .any(|operation| matches!(operation, DriverOperation::Install { .. }));
        result = apply_drivers(config);
    }
    if result.is_ok() {
        result = run_hooks(config, HookStage::AfterApply);
    }
    match result {
        Ok(()) => Ok(ApplyReport {
            message: format!(
                "live apply completed successfully; {} reversible mutation(s) recorded",
                rollback.len()
            ),
        }),
        Err(error) => {
            let had_mutations = !rollback.is_empty();
            let rollback_errors = rollback_all(rollback);
            let hook_error = run_hooks(config, HookStage::AfterRollback).err();
            let rolled_back = had_mutations
                && !irreversible_change
                && rollback_errors.is_empty()
                && hook_error.is_none();
            let mut details = vec![error.message];
            details.extend(rollback_errors);
            if let Some(error) = hook_error {
                details.push(format!("after-rollback hook failed: {}", error.message));
            }
            Err(PlatformError {
                kind: error.kind,
                message: details.join("; "),
                rolled_back,
            })
        }
    }
}

#[allow(clippy::too_many_lines)]
fn apply_reversible(
    config: &NetplanConfig,
    rollback: &mut Vec<RollbackAction>,
) -> PlatformResult<()> {
    if let Some(identity) = &config.identity {
        if let Some(name) = &identity.computer_name {
            let previous = get_computer_name(ComputerNamePhysicalDnsHostname)?;
            if !previous.eq_ignore_ascii_case(name) {
                set_computer_name(ComputerNamePhysicalDnsHostname, name)?;
                rollback.push(RollbackAction::ComputerName(previous));
            }
        }
        if let Some(workgroup) = &identity.workgroup {
            let previous = get_workgroup()?;
            if !previous.eq_ignore_ascii_case(workgroup) {
                set_workgroup(workgroup)?;
                rollback.push(RollbackAction::Workgroup(previous));
            }
        }
        if let Some(suffix) = &identity.dns_suffix {
            let previous = get_computer_name(ComputerNamePhysicalDnsDomain)?;
            if !previous.eq_ignore_ascii_case(suffix) {
                set_computer_name(ComputerNamePhysicalDnsDomain, suffix)?;
                rollback.push(RollbackAction::DnsSuffix(previous));
            }
        }
    }
    if !config.adapters.is_empty() {
        let inventory = enumerate_inventory().map_err(|error| {
            PlatformError::internal(format!("adapter apply inventory failed: {error}"))
        })?;
        for adapter in &config.adapters {
            let snapshot = resolve_adapter(&inventory, &adapter.selector)?.clone();
            if adapter.enabled == Some(true) && !snapshot.admin_enabled {
                set_adapter_enabled(&snapshot.info.name, true)?;
                rollback.push(RollbackAction::AdapterState {
                    name: snapshot.info.name.clone(),
                    enabled: false,
                });
            }
            let enabled_during_apply = adapter.enabled == Some(true) || snapshot.admin_enabled;
            if let Some(mac) = &adapter.mac_address {
                let key =
                    find_adapter_class_key(snapshot.info.guid.as_deref().ok_or_else(|| {
                        PlatformError::invalid_config("selected adapter has no stable Windows GUID")
                    })?)?;
                let previous = read_registry_text(&key, "NetworkAddress", RRF_RT_REG_SZ)?;
                set_registry_string(&key, "NetworkAddress", &canonical_mac(mac))?;
                rollback.push(RollbackAction::AdapterMac {
                    key,
                    previous,
                    name: snapshot.info.name.clone(),
                    restart: enabled_during_apply,
                });
                if enabled_during_apply {
                    restart_adapter(&snapshot.info.name)?;
                }
            }
            if let Some(ipv4) = &adapter.ipv4 {
                let mut restore = NetworkRestore::capture(&snapshot)?;
                restore.record_targets(ipv4);
                rollback.push(RollbackAction::AdapterIpv4(Box::new(restore.clone())));
                let changed = apply_ipv4(&restore, ipv4)?;
                if !changed {
                    let _ = rollback.pop();
                }
            }
            if adapter.enabled == Some(false) && snapshot.admin_enabled {
                set_adapter_enabled(&snapshot.info.name, false)?;
                rollback.push(RollbackAction::AdapterState {
                    name: snapshot.info.name.clone(),
                    enabled: true,
                });
            }
        }
    }
    apply_wifi(config, rollback)?;
    for service in &config.services {
        let was_running = service_is_running(&service.name)?;
        let should_run = service.state == ServiceState::Running;
        if was_running != should_run {
            rollback.push(RollbackAction::Service {
                name: service.name.clone(),
                running: was_running,
            });
            set_service_running(&service.name, should_run)?;
        }
    }
    for account in &config.smb.accounts {
        if let Some(action) = smb::apply_account(account)? {
            rollback.push(RollbackAction::Smb(action));
        }
    }
    for share in &config.smb.shares {
        let action = smb::apply_share(config, share)?;
        rollback.push(RollbackAction::Smb(action));
    }
    for mapping in &config.smb.mappings {
        if let Some(action) = smb::apply_mapping(config, mapping)? {
            rollback.push(RollbackAction::Smb(action));
        }
    }
    if let Some(firewall) = &config.firewall {
        let previous = FirewallRestore::capture()?;
        if !previous.all_equal(firewall.enabled) {
            rollback.push(RollbackAction::Firewall(previous));
            set_firewall_profile("allprofiles", firewall.enabled)?;
        }
    }
    Ok(())
}

fn apply_wifi(config: &NetplanConfig, rollback: &mut Vec<RollbackAction>) -> PlatformResult<()> {
    if config.wifi.is_empty() && config.wifi_actions.is_empty() {
        return Ok(());
    }
    let inventory = enumerate_inventory().map_err(|error| {
        PlatformError::internal(format!("Wi-Fi apply inventory failed: {error}"))
    })?;
    let client = wifi::Client::open()?;
    let interfaces = client.interfaces()?;
    for profile in &config.wifi {
        let interface =
            resolve_wifi_interface(&inventory, &interfaces, profile.selector.as_ref())?.guid;
        let name = wifi::profile_name(profile).to_owned();
        let previous_xml = client.get_profile(&interface, &name)?;
        rollback.push(RollbackAction::Wifi(wifi::Rollback::Profile {
            interface,
            name,
            previous_xml,
        }));
        client.set_profile(&interface, profile)?;
    }
    for action in &config.wifi_actions {
        let selector = match action {
            WifiAction::Scan { selector }
            | WifiAction::Connect { selector, .. }
            | WifiAction::Disconnect { selector } => selector.as_ref(),
        };
        let interface = resolve_wifi_interface(&inventory, &interfaces, selector)?.guid;
        match action {
            WifiAction::Scan { .. } => client.scan(&interface)?,
            WifiAction::Connect { profile, .. } => {
                let previous_profile = client.current_profile(&interface)?;
                rollback.push(RollbackAction::Wifi(wifi::Rollback::Connection {
                    interface,
                    previous_profile,
                }));
                client.connect(&interface, profile)?;
            }
            WifiAction::Disconnect { .. } => {
                let previous_profile = client.current_profile(&interface)?;
                rollback.push(RollbackAction::Wifi(wifi::Rollback::Connection {
                    interface,
                    previous_profile,
                }));
                client.disconnect(&interface)?;
            }
        }
    }
    Ok(())
}

fn run_hooks(config: &NetplanConfig, stage: HookStage) -> PlatformResult<()> {
    for hook in config.hooks.iter().filter(|hook| hook.stage == stage) {
        run_hook(hook)?;
    }
    Ok(())
}

fn run_hook(hook: &HookConfig) -> PlatformResult<()> {
    let mut command = Command::new(&hook.program);
    command
        .args(&hook.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if hook.wait {
        let status = command
            .status()
            .map_err(|error| process_error("hook", &error))?;
        if !status.success() {
            return Err(PlatformError::internal(format!(
                "hook {:?} exited with status {status}",
                hook.program
            )));
        }
    } else {
        command
            .spawn()
            .map_err(|error| process_error("hook", &error))?;
    }
    Ok(())
}

fn get_computer_name(format: COMPUTER_NAME_FORMAT) -> PlatformResult<String> {
    let mut length = 0_u32;
    // SAFETY: The first call intentionally supplies no buffer and a valid size pointer.
    let _ = unsafe { GetComputerNameExW(format, None, &raw mut length) };
    if length == 0 {
        return Err(windows_last_error("GetComputerNameExW size probe"));
    }
    let mut buffer = vec![0_u16; length as usize];
    // SAFETY: `buffer` contains `length` writable UTF-16 code units and the size pointer is valid.
    unsafe { GetComputerNameExW(format, Some(PWSTR(buffer.as_mut_ptr())), &raw mut length) }
        .map_err(|error| windows_error("GetComputerNameExW", &error))?;
    buffer.truncate(length as usize);
    String::from_utf16(&buffer)
        .map_err(|error| PlatformError::internal(format!("invalid UTF-16 computer name: {error}")))
}

fn set_computer_name(format: COMPUTER_NAME_FORMAT, value: &str) -> PlatformResult<()> {
    let value = wide(value);
    // SAFETY: `value` is NUL-terminated and remains alive for the duration of the call.
    unsafe { SetComputerNameExW(format, PCWSTR(value.as_ptr())) }
        .map_err(|error| windows_error("SetComputerNameExW", &error))
}

fn get_workgroup() -> PlatformResult<String> {
    let mut pointer = PWSTR::null();
    let mut status = NETSETUP_JOIN_STATUS::default();
    // SAFETY: Both output pointers refer to initialized writable storage. A null server selects
    // the local computer; a successful allocation is released with NetApiBufferFree below.
    let code = unsafe { NetGetJoinInformation(PCWSTR::null(), &raw mut pointer, &raw mut status) };
    if code != 0 {
        return Err(net_api_error("NetGetJoinInformation", code));
    }
    // SAFETY: NetGetJoinInformation returned a NUL-terminated allocated string on success.
    let name = unsafe { pointer.to_string() }.map_err(|error| {
        PlatformError::internal(format!(
            "NetGetJoinInformation returned invalid UTF-16: {error}"
        ))
    });
    // SAFETY: `pointer` is the allocation returned by NetGetJoinInformation and is freed once.
    let free_code = unsafe { NetApiBufferFree(Some(pointer.0.cast())) };
    if free_code != 0 {
        return Err(net_api_error("NetApiBufferFree", free_code));
    }
    if status != NetSetupWorkgroupName {
        return Err(PlatformError::invalid_config(
            "refusing to change a domain-joined machine to a workgroup without rollback credentials",
        ));
    }
    name
}

fn set_workgroup(value: &str) -> PlatformResult<()> {
    let value = wide(value);
    // SAFETY: All optional parameters are null for a local unauthenticated workgroup join and the
    // workgroup buffer is NUL-terminated for the duration of the call.
    let code = unsafe {
        NetJoinDomain(
            PCWSTR::null(),
            PCWSTR(value.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            NET_JOIN_DOMAIN_JOIN_OPTIONS(0),
        )
    };
    if code == 0 {
        Ok(())
    } else {
        Err(net_api_error("NetJoinDomain(workgroup)", code))
    }
}

pub(super) fn netsh_available() -> bool {
    system_tool("netsh.exe").is_file()
}

pub(super) fn pnputil_available() -> bool {
    system_tool("pnputil.exe").is_file()
}

pub(super) fn force_driver_available() -> bool {
    let name = wide("newdev.dll");
    // SAFETY: The DLL name is NUL-terminated and the returned reference is released below.
    let Ok(module) = (unsafe { LoadLibraryW(PCWSTR(name.as_ptr())) }) else {
        return false;
    };
    // SAFETY: The static export name is NUL-terminated and `module` is valid.
    let symbol = unsafe {
        GetProcAddress(
            module,
            PCSTR(c"UpdateDriverForPlugAndPlayDevicesW".as_ptr().cast()),
        )
    };
    // SAFETY: `module` is the owned reference returned by LoadLibraryW.
    let _ = unsafe { windows::Win32::Foundation::FreeLibrary(module) };
    symbol.is_some()
}

fn apply_drivers(config: &NetplanConfig) -> PlatformResult<()> {
    for operation in &config.drivers {
        match operation {
            DriverOperation::Install {
                inf_path,
                hardware_id,
                force,
                restart,
            } => {
                let outcome = if *force {
                    let hardware_id = hardware_id.as_deref().ok_or_else(|| {
                        PlatformError::invalid_config(
                            "forced driver replacement requires a hardware_id",
                        )
                    })?;
                    force_install_driver(inf_path, hardware_id)?
                } else {
                    run_pnputil(vec![
                        "/add-driver".into(),
                        inf_path.clone(),
                        "/install".into(),
                    ])?
                };
                let should_restart = *restart == RestartPolicy::Always
                    || (*restart == RestartPolicy::IfRequired && outcome.reboot_required);
                if should_restart {
                    let hardware_id = hardware_id.as_deref().ok_or_else(|| {
                        PlatformError::invalid_config("driver restart requires a hardware_id")
                    })?;
                    run_pnputil(vec![
                        "/restart-device".into(),
                        "/deviceid".into(),
                        hardware_id.into(),
                    ])?;
                }
            }
            DriverOperation::RestartAdapter { selector } => {
                let inventory = enumerate_inventory().map_err(|error| {
                    PlatformError::internal(format!("adapter restart inventory failed: {error}"))
                })?;
                let adapter = resolve_adapter(&inventory, selector)?;
                restart_adapter(&adapter.info.name)?;
            }
        }
    }
    Ok(())
}

fn force_install_driver(inf_path: &str, hardware_id: &str) -> PlatformResult<ToolOutcome> {
    type UpdateDriverFn = unsafe extern "system" fn(
        windows::Win32::Foundation::HWND,
        PCWSTR,
        PCWSTR,
        u32,
        *mut BOOL,
    ) -> BOOL;
    const INSTALLFLAG_FORCE: u32 = 1;
    const INSTALLFLAG_NONINTERACTIVE: u32 = 4;

    let full_path = std::fs::canonicalize(inf_path)
        .map_err(|error| process_error("canonicalize driver INF", &error))?;
    let full_path = full_path.to_str().ok_or_else(|| {
        PlatformError::invalid_config("driver INF path is not representable as Unicode")
    })?;
    let library_name = wide("newdev.dll");
    // SAFETY: The DLL name is NUL-terminated and the returned reference is released below.
    let module = unsafe { LoadLibraryW(PCWSTR(library_name.as_ptr())) }.map_err(|error| {
        PlatformError::unsupported(format!("newdev.dll is unavailable: {error}"))
    })?;
    // SAFETY: The export name is static and NUL-terminated.
    let symbol = unsafe {
        GetProcAddress(
            module,
            PCSTR(c"UpdateDriverForPlugAndPlayDevicesW".as_ptr().cast()),
        )
    };
    let result = (|| {
        let symbol = symbol.ok_or_else(|| {
            PlatformError::unsupported(
                "newdev.dll does not export UpdateDriverForPlugAndPlayDevicesW",
            )
        })?;
        // SAFETY: The named NewDev export has this documented `extern system` signature.
        let update: UpdateDriverFn = unsafe { std::mem::transmute(symbol) };
        let hardware_id = wide(hardware_id);
        let full_path = wide(full_path);
        let mut reboot_required = BOOL(0);
        // SAFETY: All strings are NUL-terminated and live for the call; a null HWND forbids UI.
        let success = unsafe {
            update(
                windows::Win32::Foundation::HWND::default(),
                PCWSTR(hardware_id.as_ptr()),
                PCWSTR(full_path.as_ptr()),
                INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE,
                &raw mut reboot_required,
            )
        };
        if success.as_bool() {
            Ok(ToolOutcome {
                reboot_required: reboot_required.as_bool(),
            })
        } else {
            Err(windows_last_error("UpdateDriverForPlugAndPlayDevicesW"))
        }
    })();
    // SAFETY: `module` is the owned reference returned by LoadLibraryW.
    let _ = unsafe { windows::Win32::Foundation::FreeLibrary(module) };
    result
}

struct ToolOutcome {
    reboot_required: bool,
}

#[allow(clippy::needless_pass_by_value)]
fn run_pnputil(args: Vec<String>) -> PlatformResult<ToolOutcome> {
    let output = Command::new(system_tool("pnputil.exe"))
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| process_error("pnputil", &error))?;
    let code = output.status.code();
    if output.status.success() || code == Some(3010) {
        Ok(ToolOutcome {
            reboot_required: code == Some(3010),
        })
    } else {
        let diagnostic = tool_diagnostic(&output);
        Err(PlatformError::internal(if diagnostic.is_empty() {
            format!("pnputil exited with status {}", output.status)
        } else {
            format!("pnputil exited with status {}: {diagnostic}", output.status)
        }))
    }
}

fn set_adapter_enabled(name: &str, enabled: bool) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "set".into(),
        "interface".into(),
        format!("name={name}"),
        format!("admin={}", if enabled { "enabled" } else { "disabled" }),
    ])
}

fn restart_adapter(name: &str) -> PlatformResult<()> {
    set_adapter_enabled(name, false)?;
    if let Err(error) = set_adapter_enabled(name, true) {
        let recovery = set_adapter_enabled(name, true);
        return Err(match recovery {
            Ok(()) => PlatformError::internal(format!(
                "adapter restart failed but the adapter was re-enabled: {}",
                error.message
            )),
            Err(recovery) => PlatformError::internal(format!(
                "adapter restart failed and re-enable recovery also failed: {}; {}",
                error.message, recovery.message
            )),
        });
    }
    Ok(())
}

fn apply_ipv4(restore: &NetworkRestore, config: &Ipv4Config) -> PlatformResult<bool> {
    let if_index = restore.snapshot.info.if_index;
    match config {
        Ipv4Config::Dhcp { dns_from_dhcp } => {
            let mut changed = false;
            if !restore.snapshot.dhcp_enabled {
                run_netsh(vec![
                    "interface".into(),
                    "ipv4".into(),
                    "set".into(),
                    "address".into(),
                    format!("name={if_index}"),
                    "source=dhcp".into(),
                ])?;
                changed = true;
            }
            if !restore.snapshot.manual_ipv4.is_empty() {
                remove_captured_network(
                    if_index,
                    &restore.snapshot.manual_ipv4,
                    &restore.snapshot.gateways,
                )?;
                changed = true;
            }
            if *dns_from_dhcp && !restore.dns_from_dhcp {
                set_dns_from_dhcp(if_index)?;
                changed = true;
            }
            if *dns_from_dhcp && !restore.wins_from_dhcp {
                set_wins_from_dhcp(if_index)?;
                changed = true;
            }
            Ok(changed)
        }
        Ipv4Config::Static {
            addresses,
            gateways,
            dns,
            wins,
        } => {
            if static_network_matches(restore, addresses, gateways, dns, wins) {
                return Ok(false);
            }
            let first = addresses.first().ok_or_else(|| {
                PlatformError::invalid_config("static IPv4 plan contains no addresses")
            })?;
            set_primary_address(
                if_index,
                &first.to_string(),
                gateways.first().map_or("none".into(), ToString::to_string),
            )?;
            for address in addresses.iter().skip(1) {
                add_address(if_index, &address.to_string())?;
            }
            for gateway in gateways.iter().skip(1) {
                add_gateway(if_index, &gateway.to_string())?;
            }
            set_dns(if_index, dns, false)?;
            set_wins(if_index, wins, false)?;
            Ok(true)
        }
    }
}

fn static_network_matches(
    restore: &NetworkRestore,
    addresses: &[ipnet::Ipv4Net],
    gateways: &[std::net::Ipv4Addr],
    dns: &[IpAddr],
    wins: &[std::net::Ipv4Addr],
) -> bool {
    !restore.dns_from_dhcp
        && !restore.wins_from_dhcp
        && manual_addresses_match(&restore.snapshot, addresses)
        && restore.snapshot.gateways == gateways
        && restore.snapshot.dns == dns
        && restore.snapshot.wins == wins
}

fn manual_addresses_match(snapshot: &AdapterSnapshot, desired: &[ipnet::Ipv4Net]) -> bool {
    snapshot.manual_ipv4.len() == desired.len()
        && snapshot
            .manual_ipv4
            .iter()
            .zip(desired)
            .all(|(actual, desired)| {
                actual.address == desired.addr().to_string()
                    && actual.prefix_length == desired.prefix_len()
            })
}

#[allow(clippy::needless_pass_by_value)]
fn set_primary_address(if_index: u32, address: &str, gateway: String) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "address".into(),
        format!("name={if_index}"),
        "source=static".into(),
        format!("address={address}"),
        format!("gateway={gateway}"),
        "store=active".into(),
    ])
}

fn add_address(if_index: u32, address: &str) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "add".into(),
        "address".into(),
        format!("name={if_index}"),
        format!("address={address}"),
        "gateway=none".into(),
        "store=active".into(),
    ])
}

fn add_gateway(if_index: u32, gateway: &str) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "add".into(),
        "route".into(),
        "prefix=0.0.0.0/0".into(),
        format!("interface={if_index}"),
        format!("nexthop={gateway}"),
        "store=active".into(),
    ])
}

fn remove_captured_network(
    if_index: u32,
    addresses: &[netplan::IpAddressInfo],
    gateways: &[std::net::Ipv4Addr],
) -> PlatformResult<()> {
    let inventory = enumerate_inventory().map_err(|error| {
        PlatformError::internal(format!("adapter cleanup inventory failed: {error}"))
    })?;
    let current = inventory
        .adapters
        .iter()
        .find(|adapter| adapter.info.if_index == if_index)
        .ok_or_else(|| {
            PlatformError::not_found(format!(
                "adapter if_index={if_index} disappeared during network cleanup"
            ))
        })?;
    for address in addresses {
        if current
            .info
            .ipv4
            .iter()
            .any(|candidate| candidate.address == address.address)
        {
            delete_address(if_index, &address.address)?;
        }
    }
    for gateway in gateways {
        if current.gateways.contains(gateway) {
            delete_gateway(if_index, *gateway)?;
        }
    }
    Ok(())
}

fn delete_address(if_index: u32, address: &str) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "delete".into(),
        "address".into(),
        format!("name={if_index}"),
        format!("address={address}"),
        "store=active".into(),
    ])
}

fn delete_gateway(if_index: u32, gateway: std::net::Ipv4Addr) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "delete".into(),
        "route".into(),
        "prefix=0.0.0.0/0".into(),
        format!("interface={if_index}"),
        format!("nexthop={gateway}"),
        "store=active".into(),
    ])
}

fn set_dns(if_index: u32, servers: &[IpAddr], from_dhcp: bool) -> PlatformResult<()> {
    if from_dhcp {
        return set_dns_from_dhcp(if_index);
    }
    let v4: Vec<String> = servers
        .iter()
        .filter_map(|server| match server {
            IpAddr::V4(address) => Some(address.to_string()),
            IpAddr::V6(_) => None,
        })
        .collect();
    let v6: Vec<String> = servers
        .iter()
        .filter_map(|server| match server {
            IpAddr::V4(_) => None,
            IpAddr::V6(address) => Some(address.to_string()),
        })
        .collect();
    set_dns_family("ipv4", if_index, &v4)?;
    set_dns_family("ipv6", if_index, &v6)
}

fn set_dns_from_dhcp(if_index: u32) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={if_index}"),
        "source=dhcp".into(),
    ])
}

fn set_dns_family(family: &str, if_index: u32, servers: &[String]) -> PlatformResult<()> {
    let first = servers.first().map_or("none", String::as_str);
    run_netsh(vec![
        "interface".into(),
        family.into(),
        "set".into(),
        "dnsservers".into(),
        format!("name={if_index}"),
        "source=static".into(),
        format!("address={first}"),
        "validate=no".into(),
    ])?;
    for (index, server) in servers.iter().enumerate().skip(1) {
        run_netsh(vec![
            "interface".into(),
            family.into(),
            "add".into(),
            "dnsservers".into(),
            format!("name={if_index}"),
            format!("address={server}"),
            format!("index={}", index + 1),
            "validate=no".into(),
        ])?;
    }
    Ok(())
}

fn set_wins(if_index: u32, servers: &[std::net::Ipv4Addr], from_dhcp: bool) -> PlatformResult<()> {
    if from_dhcp {
        return set_wins_from_dhcp(if_index);
    }
    let first = servers.first().map_or("none".into(), ToString::to_string);
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "winsservers".into(),
        format!("name={if_index}"),
        "source=static".into(),
        format!("address={first}"),
    ])?;
    for (index, server) in servers.iter().enumerate().skip(1) {
        run_netsh(vec![
            "interface".into(),
            "ipv4".into(),
            "add".into(),
            "winsservers".into(),
            format!("name={if_index}"),
            format!("address={server}"),
            format!("index={}", index + 1),
        ])?;
    }
    Ok(())
}

fn set_wins_from_dhcp(if_index: u32) -> PlatformResult<()> {
    run_netsh(vec![
        "interface".into(),
        "ipv4".into(),
        "set".into(),
        "winsservers".into(),
        format!("name={if_index}"),
        "source=dhcp".into(),
    ])
}

#[derive(Clone)]
struct NetworkRestore {
    snapshot: AdapterSnapshot,
    dns_from_dhcp: bool,
    wins_from_dhcp: bool,
    applied_addresses: Vec<std::net::Ipv4Addr>,
    applied_gateways: Vec<std::net::Ipv4Addr>,
}

impl NetworkRestore {
    fn capture(snapshot: &AdapterSnapshot) -> PlatformResult<Self> {
        let guid = snapshot.info.guid.as_deref().ok_or_else(|| {
            PlatformError::invalid_config("selected adapter has no stable Windows GUID")
        })?;
        let tcpip =
            format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}");
        let netbt =
            format!(r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{guid}");
        let dns_from_dhcp = !registry_value_has_text(&tcpip, "NameServer", RRF_RT_REG_SZ)?;
        let wins_from_dhcp =
            !registry_value_has_text(&netbt, "NameServerList", RRF_RT_REG_MULTI_SZ)?;
        Ok(Self {
            snapshot: snapshot.clone(),
            dns_from_dhcp,
            wins_from_dhcp,
            applied_addresses: Vec::new(),
            applied_gateways: Vec::new(),
        })
    }

    fn record_targets(&mut self, config: &Ipv4Config) {
        let Ipv4Config::Static {
            addresses,
            gateways,
            ..
        } = config
        else {
            return;
        };
        self.applied_addresses = addresses
            .iter()
            .map(ipnet::Ipv4Net::addr)
            .filter(|address| {
                !self
                    .snapshot
                    .manual_ipv4
                    .iter()
                    .any(|existing| existing.address == address.to_string())
            })
            .collect();
        self.applied_gateways = gateways
            .iter()
            .copied()
            .filter(|gateway| !self.snapshot.gateways.contains(gateway))
            .collect();
    }

    fn restore(self) -> PlatformResult<()> {
        let if_index = self.snapshot.info.if_index;
        let inventory = enumerate_inventory().map_err(|error| {
            PlatformError::internal(format!("adapter rollback inventory failed: {error}"))
        })?;
        let current = inventory
            .adapters
            .iter()
            .find(|adapter| adapter.info.if_index == if_index)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "adapter if_index={if_index} disappeared before rollback"
                ))
            })?;
        let current_sources = NetworkRestore::capture(current)?;
        if !self.snapshot.manual_ipv4.is_empty()
            && (!manual_snapshot_matches(current, &self.snapshot)
                || current.gateways != self.snapshot.gateways)
        {
            self.restore_static_address(if_index)?;
        } else if self.snapshot.manual_ipv4.is_empty()
            && self.snapshot.dhcp_enabled != current.dhcp_enabled
            && self.snapshot.dhcp_enabled
        {
            run_netsh(vec![
                "interface".into(),
                "ipv4".into(),
                "set".into(),
                "address".into(),
                format!("name={if_index}"),
                "source=dhcp".into(),
            ])?;
        }
        if current_sources.dns_from_dhcp != self.dns_from_dhcp
            || (!self.dns_from_dhcp && current.dns != self.snapshot.dns)
        {
            set_dns(if_index, &self.snapshot.dns, self.dns_from_dhcp)?;
        }
        if current_sources.wins_from_dhcp != self.wins_from_dhcp
            || (!self.wins_from_dhcp && current.wins != self.snapshot.wins)
        {
            set_wins(if_index, &self.snapshot.wins, self.wins_from_dhcp)?;
        }
        let inventory = enumerate_inventory().map_err(|error| {
            PlatformError::internal(format!(
                "adapter rollback cleanup inventory failed: {error}"
            ))
        })?;
        let current = inventory
            .adapters
            .iter()
            .find(|adapter| adapter.info.if_index == if_index)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "adapter if_index={if_index} disappeared during rollback"
                ))
            })?;
        for address in &self.applied_addresses {
            if current
                .info
                .ipv4
                .iter()
                .any(|candidate| candidate.address == address.to_string())
            {
                delete_address(if_index, &address.to_string())?;
            }
        }
        for gateway in &self.applied_gateways {
            if current.gateways.contains(gateway) {
                delete_gateway(if_index, *gateway)?;
            }
        }
        self.verify_restored(if_index)
    }

    fn restore_static_address(&self, if_index: u32) -> PlatformResult<()> {
        let first = self.snapshot.manual_ipv4.first().ok_or_else(|| {
            PlatformError::internal(
                "cannot restore static IPv4 adapter that had no captured address",
            )
        })?;
        let primary = format!("{}/{}", first.address, first.prefix_length);
        set_primary_address(
            if_index,
            &primary,
            self.snapshot
                .gateways
                .first()
                .map_or("none".into(), ToString::to_string),
        )?;
        for address in self.snapshot.manual_ipv4.iter().skip(1) {
            add_address(
                if_index,
                &format!("{}/{}", address.address, address.prefix_length),
            )?;
        }
        for gateway in self.snapshot.gateways.iter().skip(1) {
            add_gateway(if_index, &gateway.to_string())?;
        }
        Ok(())
    }

    fn verify_restored(&self, if_index: u32) -> PlatformResult<()> {
        let inventory = enumerate_inventory().map_err(|error| {
            PlatformError::internal(format!("adapter rollback verification failed: {error}"))
        })?;
        let current = inventory
            .adapters
            .iter()
            .find(|adapter| adapter.info.if_index == if_index)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "adapter if_index={if_index} disappeared during rollback verification"
                ))
            })?;
        let current_sources = NetworkRestore::capture(current)?;
        let address_restored = if self.snapshot.manual_ipv4.is_empty() {
            self.applied_addresses.iter().all(|address| {
                current
                    .info
                    .ipv4
                    .iter()
                    .all(|candidate| candidate.address != address.to_string())
            })
        } else {
            manual_snapshot_matches(current, &self.snapshot)
                && current.gateways == self.snapshot.gateways
        };
        let dns_restored = current_sources.dns_from_dhcp == self.dns_from_dhcp
            && (self.dns_from_dhcp || current.dns == self.snapshot.dns);
        let wins_restored = current_sources.wins_from_dhcp == self.wins_from_dhcp
            && (self.wins_from_dhcp || current.wins == self.snapshot.wins);
        if current.dhcp_enabled == self.snapshot.dhcp_enabled
            && address_restored
            && dns_restored
            && wins_restored
        {
            Ok(())
        } else {
            Err(PlatformError::internal(format!(
                "adapter if_index={if_index} did not match its captured logical network state after rollback"
            )))
        }
    }
}

fn manual_snapshot_matches(current: &AdapterSnapshot, desired: &AdapterSnapshot) -> bool {
    current.manual_ipv4 == desired.manual_ipv4
}

struct FirewallRestore {
    domain: bool,
    private: bool,
    public: bool,
}

impl FirewallRestore {
    fn capture() -> PlatformResult<Self> {
        const BASE: &str =
            r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        Ok(Self {
            domain: read_registry_dword(&format!(r"{BASE}\DomainProfile"), "EnableFirewall")? != 0,
            private: read_registry_dword(&format!(r"{BASE}\StandardProfile"), "EnableFirewall")?
                != 0,
            public: read_registry_dword(&format!(r"{BASE}\PublicProfile"), "EnableFirewall")? != 0,
        })
    }

    const fn all_equal(&self, enabled: bool) -> bool {
        self.domain == enabled && self.private == enabled && self.public == enabled
    }

    fn restore(self) -> PlatformResult<()> {
        set_firewall_profile("domainprofile", self.domain)?;
        set_firewall_profile("privateprofile", self.private)?;
        set_firewall_profile("publicprofile", self.public)
    }
}

fn set_firewall_profile(profile: &str, enabled: bool) -> PlatformResult<()> {
    run_netsh(vec![
        "advfirewall".into(),
        "set".into(),
        profile.into(),
        "state".into(),
        if enabled { "on" } else { "off" }.into(),
    ])
}

fn read_registry_dword(subkey: &str, value: &str) -> PlatformResult<u32> {
    let subkey = wide(subkey);
    let value = wide(value);
    let mut data = 0_u32;
    let mut bytes = u32::try_from(std::mem::size_of::<u32>()).unwrap_or(4);
    // SAFETY: The strings are NUL-terminated, `data` is a writable DWORD, and `bytes` contains
    // its exact capacity.
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut data).cast::<c_void>()),
            Some(&raw mut bytes),
        )
    };
    if result.0 == 0 {
        Ok(data)
    } else {
        Err(registry_error("RegGetValueW(DWORD)", result.0))
    }
}

fn find_adapter_class_key(guid: &str) -> PlatformResult<String> {
    const CLASS: &str =
        r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    for index in 0..10_000 {
        let key = format!(r"{CLASS}\{index:04}");
        if read_registry_text(&key, "NetCfgInstanceId", RRF_RT_REG_SZ)?.is_some_and(|value| {
            value
                .trim_matches(['{', '}'])
                .eq_ignore_ascii_case(guid.trim_matches(['{', '}']))
        }) {
            return Ok(key);
        }
    }
    Err(PlatformError::not_found(format!(
        "adapter registry class key was not found for GUID {guid:?}"
    )))
}

fn read_registry_text(
    subkey: &str,
    value: &str,
    flags: REG_ROUTINE_FLAGS,
) -> PlatformResult<Option<String>> {
    let subkey = wide(subkey);
    let value = wide(value);
    let mut bytes = 0_u32;
    // SAFETY: The strings are NUL-terminated and the size probe provides valid output storage.
    let probe = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            None,
            Some(&raw mut bytes),
        )
    };
    if probe.0 == 2 {
        return Ok(None);
    }
    if probe.0 != 0 {
        return Err(registry_error("RegGetValueW text size probe", probe.0));
    }
    let mut buffer = vec![0_u16; (bytes as usize).div_ceil(2)];
    // SAFETY: The buffer has the probed capacity and all pointers are valid for the call.
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            Some(&raw mut bytes),
        )
    };
    if result.0 != 0 {
        return Err(registry_error("RegGetValueW text", result.0));
    }
    let used = (bytes as usize / 2).min(buffer.len());
    let end = buffer[..used]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(used);
    String::from_utf16(&buffer[..end])
        .map(Some)
        .map_err(|error| PlatformError::internal(format!("invalid registry UTF-16: {error}")))
}

fn set_registry_string(subkey: &str, value: &str, data: &str) -> PlatformResult<()> {
    let subkey = wide(subkey);
    let value = wide(value);
    let data = wide(data);
    let bytes = u32::try_from(data.len().saturating_mul(2)).map_err(|_| {
        PlatformError::invalid_config("registry string exceeds the Windows DWORD size limit")
    })?;
    // SAFETY: All strings are NUL-terminated and the byte count covers the complete UTF-16 data.
    let result = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            REG_SZ.0,
            Some(data.as_ptr().cast::<c_void>()),
            bytes,
        )
    };
    if result.0 == 0 {
        Ok(())
    } else {
        Err(registry_error("RegSetKeyValueW", result.0))
    }
}

fn delete_registry_value(subkey: &str, value: &str) -> PlatformResult<()> {
    let subkey = wide(subkey);
    let value = wide(value);
    // SAFETY: Both strings are valid NUL-terminated registry paths.
    let result = unsafe {
        RegDeleteKeyValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
        )
    };
    if result.0 == 0 || result.0 == 2 {
        Ok(())
    } else {
        Err(registry_error("RegDeleteKeyValueW", result.0))
    }
}

fn registry_value_has_text(
    subkey: &str,
    value: &str,
    flags: REG_ROUTINE_FLAGS,
) -> PlatformResult<bool> {
    let subkey = wide(subkey);
    let value = wide(value);
    let mut bytes = 0_u32;
    // SAFETY: The key and value strings are NUL-terminated, and the size probe supplies no data
    // buffer while providing valid storage for the required byte count.
    let probe = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            None,
            Some(&raw mut bytes),
        )
    };
    if probe.0 == 2 {
        return Ok(false);
    }
    if probe.0 != 0 {
        return Err(registry_error("RegGetValueW size probe", probe.0));
    }
    if bytes == 0 {
        return Ok(false);
    }
    let mut buffer = vec![0_u16; (bytes as usize).div_ceil(2)];
    // SAFETY: The buffer has at least the probed byte capacity and all pointer arguments remain
    // valid for the duration of the call.
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            Some(&raw mut bytes),
        )
    };
    if result.0 != 0 {
        return Err(registry_error("RegGetValueW", result.0));
    }
    let used = (bytes as usize / 2).min(buffer.len());
    Ok(buffer[..used].iter().any(|unit| *unit != 0))
}

#[allow(clippy::needless_pass_by_value)]
fn run_netsh(args: Vec<String>) -> PlatformResult<()> {
    let tool = system_tool("netsh.exe");
    let output = Command::new(&tool)
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| process_error("netsh", &error))?;
    if output.status.success() {
        Ok(())
    } else {
        let diagnostic = tool_diagnostic(&output);
        Err(PlatformError::internal(if diagnostic.is_empty() {
            format!("netsh exited with status {}", output.status)
        } else {
            format!("netsh exited with status {}: {diagnostic}", output.status)
        }))
    }
}

fn tool_diagnostic(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = stderr.trim();
    let stdout = stdout.trim();
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout.to_owned(),
        (true, false) => stderr.to_owned(),
        (false, false) => format!("{stderr}; {stdout}"),
    }
}

fn system_tool(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot").map_or_else(
        || PathBuf::from(name),
        |root| PathBuf::from(root).join("System32").join(name),
    )
}

fn service_is_running(name: &str) -> PlatformResult<bool> {
    let manager = ServiceHandle::open_manager()?;
    let service = ServiceHandle::open_service(&manager, name)?;
    Ok(query_service(&service)?.dwCurrentState == SERVICE_RUNNING)
}

pub(super) fn service_available(name: &str) -> PlatformResult<()> {
    let manager = ServiceHandle::open_manager()?;
    let _service = ServiceHandle::open_service(&manager, name)?;
    Ok(())
}

fn set_service_running(name: &str, running: bool) -> PlatformResult<()> {
    let manager = ServiceHandle::open_manager()?;
    let service = ServiceHandle::open_service(&manager, name)?;
    let current = query_service(&service)?.dwCurrentState;
    if running && current != SERVICE_RUNNING {
        // SAFETY: The service handle has SERVICE_START access and no arguments are supplied.
        unsafe { StartServiceW(service.0, None) }
            .map_err(|error| windows_error("StartServiceW", &error))?;
        wait_for_service_state(&service, SERVICE_RUNNING)?;
    } else if !running && current != SERVICE_STOPPED {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: The service handle has SERVICE_STOP access and `status` is writable storage.
        unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &raw mut status) }
            .map_err(|error| windows_error("ControlService(STOP)", &error))?;
        wait_for_service_state(&service, SERVICE_STOPPED)?;
    }
    Ok(())
}

fn query_service(service: &ServiceHandle) -> PlatformResult<SERVICE_STATUS> {
    let mut status = SERVICE_STATUS::default();
    // SAFETY: `status` points to initialized writable storage and the handle has query access.
    unsafe { QueryServiceStatus(service.0, &raw mut status) }
        .map_err(|error| windows_error("QueryServiceStatus", &error))?;
    Ok(status)
}

fn wait_for_service_state(
    service: &ServiceHandle,
    desired: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
) -> PlatformResult<()> {
    let deadline = Instant::now() + SERVICE_WAIT_TIMEOUT;
    loop {
        let current = query_service(service)?.dwCurrentState;
        if current == desired {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(PlatformError::internal(format!(
                "service did not reach state {} within {} seconds",
                desired.0,
                SERVICE_WAIT_TIMEOUT.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    fn open_manager() -> PlatformResult<Self> {
        // SAFETY: Null names select the local active service-control database.
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map(Self)
            .map_err(|error| windows_error("OpenSCManagerW", &error))
    }

    fn open_service(manager: &Self, name: &str) -> PlatformResult<Self> {
        let name = wide(name);
        // SAFETY: The manager is valid and the service name is NUL-terminated.
        unsafe {
            OpenServiceW(
                manager.0,
                PCWSTR(name.as_ptr()),
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
            )
        }
        .map(Self)
        .map_err(|error| windows_error("OpenServiceW", &error))
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: The handle is owned by this wrapper and is closed exactly once.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

enum RollbackAction {
    ComputerName(String),
    Workgroup(String),
    DnsSuffix(String),
    AdapterState {
        name: String,
        enabled: bool,
    },
    AdapterIpv4(Box<NetworkRestore>),
    AdapterMac {
        key: String,
        previous: Option<String>,
        name: String,
        restart: bool,
    },
    Firewall(FirewallRestore),
    Service {
        name: String,
        running: bool,
    },
    Wifi(wifi::Rollback),
    Smb(smb::Rollback),
}

impl RollbackAction {
    fn execute(self) -> PlatformResult<()> {
        match self {
            Self::ComputerName(value) => set_computer_name(ComputerNamePhysicalDnsHostname, &value),
            Self::Workgroup(value) => set_workgroup(&value),
            Self::DnsSuffix(value) => set_computer_name(ComputerNamePhysicalDnsDomain, &value),
            Self::AdapterState { name, enabled } => set_adapter_enabled(&name, enabled),
            Self::AdapterIpv4(restore) => (*restore).restore(),
            Self::AdapterMac {
                key,
                previous,
                name,
                restart,
            } => {
                match previous {
                    Some(value) => set_registry_string(&key, "NetworkAddress", &value)?,
                    None => delete_registry_value(&key, "NetworkAddress")?,
                }
                if restart {
                    restart_adapter(&name)?;
                }
                Ok(())
            }
            Self::Firewall(restore) => restore.restore(),
            Self::Service { name, running } => set_service_running(&name, running),
            Self::Wifi(action) => action.execute(),
            Self::Smb(action) => action.execute(),
        }
    }
}

fn rollback_all(rollback: Vec<RollbackAction>) -> Vec<String> {
    rollback
        .into_iter()
        .rev()
        .filter_map(|action| action.execute().err())
        .map(|error| format!("rollback failed: {}", error.message))
        .collect()
}

fn process_error(context: &str, error: &std::io::Error) -> PlatformError {
    match error.kind() {
        std::io::ErrorKind::NotFound => {
            PlatformError::not_found(format!("{context} executable was not found: {error}"))
        }
        std::io::ErrorKind::PermissionDenied => {
            PlatformError::permission_denied(format!("{context} execution was denied: {error}"))
        }
        _ => PlatformError::internal(format!("{context} execution failed: {error}")),
    }
}

fn windows_last_error(context: &str) -> PlatformError {
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(2 | 1060) => PlatformError::not_found(format!("{context} failed: {error}")),
        Some(5) => PlatformError::permission_denied(format!("{context} failed: {error}")),
        _ => PlatformError::internal(format!("{context} failed: {error}")),
    }
}

fn windows_error(context: &str, error: &windows::core::Error) -> PlatformError {
    let win32 = u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff;
    match win32 {
        2 | 1060 => PlatformError::not_found(format!("{context} failed: {error}")),
        5 => PlatformError::permission_denied(format!("{context} failed: {error}")),
        _ => PlatformError::internal(format!("{context} failed: {error}")),
    }
}

fn net_api_error(context: &str, code: u32) -> PlatformError {
    match code {
        5 => PlatformError::permission_denied(format!("{context} failed with status {code}")),
        2 | 2221 => PlatformError::not_found(format!("{context} failed with status {code}")),
        _ => PlatformError::internal(format!("{context} failed with status {code}")),
    }
}

fn registry_error(context: &str, code: u32) -> PlatformError {
    match code {
        2 => PlatformError::not_found(format!("{context} failed with status {code}")),
        5 => PlatformError::permission_denied(format!("{context} failed with status {code}")),
        _ => PlatformError::internal(format!("{context} failed with status {code}")),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
