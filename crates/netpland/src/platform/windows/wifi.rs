//! Runtime-loaded Native Wi-Fi support.
//!
//! `wlanapi.dll` is optional in trimmed Windows PE images. Loading it dynamically keeps the
//! daemon executable usable when wireless networking is absent while retaining typed API calls
//! when the component and `WlanSvc` are available.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use netplan::config::{SecretRef, WifiAuthentication, WifiProfile};
use netplan::{WifiInterfaceStatus, WifiNetwork};
use windows::Win32::Foundation::{
    ERROR_NDIS_DOT11_POWER_STATE_INVALID, FreeLibrary, HANDLE, HMODULE,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToIndex,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::NetworkManagement::WiFi::{
    DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_AUTH_ALGO_OWE,
    DOT11_AUTH_ALGO_RSNA, DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA_NONE,
    DOT11_AUTH_ALGO_WPA_PSK, DOT11_AUTH_ALGO_WPA3, DOT11_AUTH_ALGO_WPA3_ENT,
    DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGO_BIP,
    DOT11_CIPHER_ALGO_BIP_CMAC_256, DOT11_CIPHER_ALGO_BIP_GMAC_128, DOT11_CIPHER_ALGO_BIP_GMAC_256,
    DOT11_CIPHER_ALGO_CCMP, DOT11_CIPHER_ALGO_CCMP_256, DOT11_CIPHER_ALGO_GCMP,
    DOT11_CIPHER_ALGO_GCMP_256, DOT11_CIPHER_ALGO_NONE, DOT11_CIPHER_ALGO_RSN_USE_GROUP,
    DOT11_CIPHER_ALGO_TKIP, DOT11_CIPHER_ALGO_WEP, DOT11_CIPHER_ALGO_WEP40,
    DOT11_CIPHER_ALGO_WEP104, DOT11_CIPHER_ALGORITHM, DOT11_SSID, L2_NOTIFICATION_DATA,
    WLAN_AVAILABLE_NETWORK, WLAN_AVAILABLE_NETWORK_CONNECTED, WLAN_AVAILABLE_NETWORK_LIST,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_CONNECTION_PARAMETERS, WLAN_INTERFACE_INFO_LIST,
    WLAN_INTERFACE_STATE, WLAN_INTF_OPCODE, WLAN_NOTIFICATION_SOURCE_ACM,
    WLAN_NOTIFICATION_SOURCE_NONE, WLAN_NOTIFICATION_SOURCES, WLAN_RADIO_STATE,
    dot11_BSS_type_infrastructure, dot11_radio_state_off, dot11_radio_state_on,
    wlan_connection_mode_profile, wlan_interface_state_ad_hoc_network_formed,
    wlan_interface_state_associating, wlan_interface_state_authenticating,
    wlan_interface_state_connected, wlan_interface_state_disconnected,
    wlan_interface_state_disconnecting, wlan_interface_state_discovering,
    wlan_interface_state_not_ready, wlan_intf_opcode_current_connection,
    wlan_intf_opcode_radio_state, wlan_notification_acm_scan_complete,
    wlan_notification_acm_scan_fail,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{BOOL, GUID, PCSTR, PCWSTR, PWSTR};

use super::super::{PlatformError, PlatformErrorKind, PlatformResult};

const WLAN_CLIENT_VERSION_LONGHORN: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_INVALID_STATE: u32 = 5023;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const HEX: &[u8; 16] = b"0123456789ABCDEF";

type WlanOpenHandleFn = unsafe extern "system" fn(u32, *const c_void, *mut u32, *mut HANDLE) -> u32;
type WlanCloseHandleFn = unsafe extern "system" fn(HANDLE, *const c_void) -> u32;
type WlanFreeMemoryFn = unsafe extern "system" fn(*const c_void);
type WlanEnumInterfacesFn =
    unsafe extern "system" fn(HANDLE, *const c_void, *mut *mut WLAN_INTERFACE_INFO_LIST) -> u32;
type WlanGetProfileFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    PCWSTR,
    *const c_void,
    *mut PWSTR,
    *mut u32,
    *mut u32,
) -> u32;
type WlanSetProfileFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    u32,
    PCWSTR,
    PCWSTR,
    BOOL,
    *const c_void,
    *mut u32,
) -> u32;
type WlanDeleteProfileFn =
    unsafe extern "system" fn(HANDLE, *const GUID, PCWSTR, *const c_void) -> u32;
type WlanScanFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    *const c_void,
    *const c_void,
    *const c_void,
) -> u32;
type WlanConnectFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    *const WLAN_CONNECTION_PARAMETERS,
    *const c_void,
) -> u32;
type WlanDisconnectFn = unsafe extern "system" fn(HANDLE, *const GUID, *const c_void) -> u32;
type WlanQueryInterfaceFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    WLAN_INTF_OPCODE,
    *const c_void,
    *mut u32,
    *mut *mut c_void,
    *mut c_void,
) -> u32;
type WlanGetAvailableNetworkListFn = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    u32,
    *const c_void,
    *mut *mut WLAN_AVAILABLE_NETWORK_LIST,
) -> u32;
type WlanRegisterNotificationFn = unsafe extern "system" fn(
    HANDLE,
    WLAN_NOTIFICATION_SOURCES,
    BOOL,
    Option<unsafe extern "system" fn(*mut L2_NOTIFICATION_DATA, *mut c_void)>,
    *const c_void,
    *const c_void,
    *mut u32,
) -> u32;

/// Confirm that the optional DLL, `AutoConfig` service, and an enabled WLAN interface are usable.
pub(super) fn probe() -> Result<(), String> {
    (|| {
        let client = Client::open()?;
        let interfaces = client.interfaces()?;
        if interfaces.is_empty() {
            Err(PlatformError::not_found(
                "no enabled Native Wi-Fi interface was discovered",
            ))
        } else {
            Ok(())
        }
    })()
    .map_err(|error| error.message)
}

#[derive(Clone, Debug)]
pub(super) struct Interface {
    pub(super) guid: GUID,
    pub(super) if_index: u32,
    pub(super) description: String,
    pub(super) state: WLAN_INTERFACE_STATE,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RadioState {
    On,
    Off,
    Unknown,
}

pub(super) struct Client {
    library: HMODULE,
    handle: HANDLE,
    close_handle: WlanCloseHandleFn,
    free_memory: WlanFreeMemoryFn,
    enum_interfaces: WlanEnumInterfacesFn,
    get_profile: WlanGetProfileFn,
    set_profile: WlanSetProfileFn,
    delete_profile: WlanDeleteProfileFn,
    scan: WlanScanFn,
    connect: WlanConnectFn,
    disconnect: WlanDisconnectFn,
    query_interface: WlanQueryInterfaceFn,
    get_available_network_list: WlanGetAvailableNetworkListFn,
    register_notification: WlanRegisterNotificationFn,
}

impl Client {
    pub(super) fn open() -> PlatformResult<Self> {
        let name = wide("wlanapi.dll");
        // SAFETY: `name` is a valid NUL-terminated DLL name. The owned module is freed in Drop.
        let library = unsafe { LoadLibraryW(PCWSTR(name.as_ptr())) }.map_err(|error| {
            PlatformError::unsupported(format!(
                "Native Wi-Fi is unavailable because wlanapi.dll could not be loaded: {error}"
            ))
        })?;
        let result = (|| {
            let open_handle = load_symbol::<WlanOpenHandleFn>(library, b"WlanOpenHandle\0")?;
            let close_handle = load_symbol::<WlanCloseHandleFn>(library, b"WlanCloseHandle\0")?;
            let free_memory = load_symbol::<WlanFreeMemoryFn>(library, b"WlanFreeMemory\0")?;
            let enum_interfaces =
                load_symbol::<WlanEnumInterfacesFn>(library, b"WlanEnumInterfaces\0")?;
            let get_profile = load_symbol::<WlanGetProfileFn>(library, b"WlanGetProfile\0")?;
            let set_profile = load_symbol::<WlanSetProfileFn>(library, b"WlanSetProfile\0")?;
            let delete_profile =
                load_symbol::<WlanDeleteProfileFn>(library, b"WlanDeleteProfile\0")?;
            let scan = load_symbol::<WlanScanFn>(library, b"WlanScan\0")?;
            let connect = load_symbol::<WlanConnectFn>(library, b"WlanConnect\0")?;
            let disconnect = load_symbol::<WlanDisconnectFn>(library, b"WlanDisconnect\0")?;
            let query_interface =
                load_symbol::<WlanQueryInterfaceFn>(library, b"WlanQueryInterface\0")?;
            let get_available_network_list = load_symbol::<WlanGetAvailableNetworkListFn>(
                library,
                b"WlanGetAvailableNetworkList\0",
            )?;
            let register_notification =
                load_symbol::<WlanRegisterNotificationFn>(library, b"WlanRegisterNotification\0")?;
            let mut negotiated = 0_u32;
            let mut handle = HANDLE::default();
            // SAFETY: Both output pointers are writable and the reserved pointer is null.
            let code = unsafe {
                open_handle(
                    WLAN_CLIENT_VERSION_LONGHORN,
                    ptr::null(),
                    &raw mut negotiated,
                    &raw mut handle,
                )
            };
            wlan_result("WlanOpenHandle", code)?;
            Ok(Self {
                library,
                handle,
                close_handle,
                free_memory,
                enum_interfaces,
                get_profile,
                set_profile,
                delete_profile,
                scan,
                connect,
                disconnect,
                query_interface,
                get_available_network_list,
                register_notification,
            })
        })();
        if result.is_err() {
            // SAFETY: `library` was successfully loaded above and ownership has not moved.
            let _ = unsafe { FreeLibrary(library) };
        }
        result
    }

    pub(super) fn interfaces(&self) -> PlatformResult<Vec<Interface>> {
        let mut list = ptr::null_mut::<WLAN_INTERFACE_INFO_LIST>();
        // SAFETY: The client handle is valid, the reserved pointer is null, and `list` is a
        // writable output pointer. A successful WLAN allocation is released below.
        let code = unsafe { (self.enum_interfaces)(self.handle, ptr::null(), &raw mut list) };
        wlan_result("WlanEnumInterfaces", code)?;
        if list.is_null() {
            return Err(PlatformError::internal(
                "WlanEnumInterfaces returned a null interface list",
            ));
        }
        let result = (|| {
            // SAFETY: The API returned a WLAN-owned list allocation on success.
            let count = unsafe { (*list).dwNumberOfItems };
            if count > 256 {
                return Err(PlatformError::internal(
                    "Native Wi-Fi interface list exceeded the traversal limit",
                ));
            }
            let mut interfaces = Vec::with_capacity(usize::try_from(count).unwrap_or_default());
            // SAFETY: `InterfaceInfo` is the first item of the variable-size API allocation.
            let first = unsafe { (*list).InterfaceInfo.as_ptr() };
            for index in 0..count {
                // SAFETY: The API guarantees `dwNumberOfItems` contiguous interface records.
                let info = unsafe { &*first.add(index as usize) };
                interfaces.push(Interface {
                    guid: info.InterfaceGuid,
                    if_index: interface_index(&info.InterfaceGuid)?,
                    description: fixed_wide(&info.strInterfaceDescription)?,
                    state: info.isState,
                });
            }
            Ok(interfaces)
        })();
        // SAFETY: `list` is the WLAN allocation returned above and is released exactly once.
        unsafe { (self.free_memory)(list.cast()) };
        result
    }

    pub(super) fn get_profile(
        &self,
        interface: &GUID,
        name: &str,
    ) -> PlatformResult<Option<String>> {
        let name = wide(name);
        let mut xml = PWSTR::null();
        let mut flags = 0_u32;
        let mut access = 0_u32;
        // SAFETY: The client and interface are valid, all output pointers are writable, and the
        // profile name remains alive. Successful API memory is released below.
        let code = unsafe {
            (self.get_profile)(
                self.handle,
                interface,
                PCWSTR(name.as_ptr()),
                ptr::null(),
                &raw mut xml,
                &raw mut flags,
                &raw mut access,
            )
        };
        if code == ERROR_NOT_FOUND {
            return Ok(None);
        }
        wlan_result("WlanGetProfile", code)?;
        // SAFETY: On success WlanGetProfile returns a NUL-terminated WLAN allocation.
        let decoded = unsafe { xml.to_string() }.map_err(|error| {
            PlatformError::internal(format!("WlanGetProfile returned invalid UTF-16: {error}"))
        });
        // SAFETY: `xml` is the allocation returned by WlanGetProfile and is released once.
        unsafe { (self.free_memory)(xml.0.cast()) };
        decoded.map(Some)
    }

    pub(super) fn set_profile_xml(&self, interface: &GUID, xml: &str) -> PlatformResult<()> {
        let xml = wide(xml);
        let mut reason = 0_u32;
        // SAFETY: The client/interface are valid and XML is a live NUL-terminated UTF-16 string.
        let code = unsafe {
            (self.set_profile)(
                self.handle,
                interface,
                0,
                PCWSTR(xml.as_ptr()),
                PCWSTR::null(),
                BOOL(1),
                ptr::null(),
                &raw mut reason,
            )
        };
        if code == 0 && reason == 0 {
            Ok(())
        } else if code != 0 {
            wlan_result("WlanSetProfile", code)
        } else {
            Err(PlatformError::invalid_config(format!(
                "WlanSetProfile rejected the profile with WLAN reason code {reason}"
            )))
        }
    }

    pub(super) fn set_profile(
        &self,
        interface: &GUID,
        profile: &WifiProfile,
    ) -> PlatformResult<()> {
        self.set_profile_xml(interface, &profile_xml(profile)?)
    }

    pub(super) fn delete_profile(&self, interface: &GUID, name: &str) -> PlatformResult<()> {
        let name = wide(name);
        // SAFETY: The client/interface are valid and the profile name is NUL-terminated.
        let code = unsafe {
            (self.delete_profile)(self.handle, interface, PCWSTR(name.as_ptr()), ptr::null())
        };
        if code == ERROR_NOT_FOUND {
            Ok(())
        } else {
            wlan_result("WlanDeleteProfile", code)
        }
    }

    pub(super) fn scan(&self, interface: &GUID) -> PlatformResult<()> {
        if self.radio_state(interface)? == RadioState::Off {
            return wlan_result("WlanScan", ERROR_NDIS_DOT11_POWER_STATE_INVALID.0);
        }
        // SAFETY: The client/interface are valid. Null optional arguments request a general scan.
        let code = unsafe {
            (self.scan)(
                self.handle,
                interface,
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        wlan_result("WlanScan", code)
    }

    pub(super) fn scan_and_wait(
        &self,
        interface: &GUID,
        timeout: Duration,
    ) -> PlatformResult<bool> {
        let (sender, receiver) = mpsc::channel();
        let context = Box::new(ScanContext {
            interface: *interface,
            sender,
        });
        let context_pointer = ptr::from_ref(context.as_ref()).cast::<c_void>();
        let mut previous_source = 0_u32;
        // SAFETY: The callback context remains alive until notifications are unregistered below.
        let register_code = unsafe {
            (self.register_notification)(
                self.handle,
                WLAN_NOTIFICATION_SOURCE_ACM,
                BOOL(1),
                Some(scan_notification),
                context_pointer,
                ptr::null(),
                &raw mut previous_source,
            )
        };
        wlan_result("WlanRegisterNotification", register_code)?;

        let scan_result = self.scan(interface);
        let notification_result = if scan_result.is_ok() {
            match receiver.recv_timeout(timeout) {
                Ok(ScanEvent::Complete) => Ok(true),
                Ok(ScanEvent::Failed(reason)) => Err(PlatformError::internal(format!(
                    "Native Wi-Fi scan failed with WLAN reason code {reason}"
                ))),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(false),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(PlatformError::internal(
                    "Native Wi-Fi scan notification channel disconnected",
                )),
            }
        } else {
            scan_result.map(|()| false)
        };

        // SAFETY: Replacing the source with NONE unregisters the callback. Windows waits for an
        // active callback to return, so the boxed context can be dropped immediately afterward.
        let unregister_code = unsafe {
            (self.register_notification)(
                self.handle,
                WLAN_NOTIFICATION_SOURCE_NONE,
                BOOL(1),
                None,
                ptr::null(),
                ptr::null(),
                &raw mut previous_source,
            )
        };
        let unregister_result =
            wlan_result("WlanRegisterNotification(unregister)", unregister_code);
        drop(context);
        match (notification_result, unregister_result) {
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            (Ok(refreshed), Ok(())) => Ok(refreshed),
        }
    }

    pub(super) fn interface_status(
        &self,
        interface: &GUID,
        state: WLAN_INTERFACE_STATE,
        if_index: u32,
        name: &str,
        guid: Option<String>,
    ) -> PlatformResult<WifiInterfaceStatus> {
        let radio_state = self.radio_state(interface)?;
        let connection = if radio_state == RadioState::Off {
            None
        } else {
            self.current_connection(interface)?
        };
        let connected = connection
            .as_ref()
            .filter(|attributes| attributes.isState == wlan_interface_state_connected);
        let ssid = connected
            .map(|attributes| ssid_parts(&attributes.wlanAssociationAttributes.dot11Ssid))
            .transpose()?;
        Ok(WifiInterfaceStatus {
            if_index,
            name: name.to_owned(),
            guid,
            state: effective_interface_state(state, radio_state).to_owned(),
            profile_name: connected
                .map(|attributes| fixed_wide(&attributes.strProfileName))
                .transpose()?
                .filter(|value| !value.is_empty()),
            ssid: ssid.as_ref().map(|(display, _)| display.clone()),
            ssid_hex: ssid.map(|(_, hex)| hex),
            signal_quality: connected
                .map(|attributes| quality(attributes.wlanAssociationAttributes.wlanSignalQuality)),
            security_enabled: connected
                .map(|attributes| attributes.wlanSecurityAttributes.bSecurityEnabled.as_bool()),
            authentication: connected
                .map(|attributes| auth_name(attributes.wlanSecurityAttributes.dot11AuthAlgorithm)),
            cipher: connected.map(|attributes| {
                cipher_name(attributes.wlanSecurityAttributes.dot11CipherAlgorithm)
            }),
            rx_rate_kbps: connected.map(|attributes| attributes.wlanAssociationAttributes.ulRxRate),
            tx_rate_kbps: connected.map(|attributes| attributes.wlanAssociationAttributes.ulTxRate),
        })
    }

    pub(super) fn available_networks(
        &self,
        interface: &GUID,
        if_index: u32,
        interface_name: &str,
    ) -> PlatformResult<Vec<WifiNetwork>> {
        let mut list = ptr::null_mut::<WLAN_AVAILABLE_NETWORK_LIST>();
        // SAFETY: The output pointer is writable and the interface/client remain valid.
        let code = unsafe {
            (self.get_available_network_list)(self.handle, interface, 0, ptr::null(), &raw mut list)
        };
        wlan_result("WlanGetAvailableNetworkList", code)?;
        if list.is_null() {
            return Err(PlatformError::internal(
                "WlanGetAvailableNetworkList returned a null list",
            ));
        }
        let result = (|| {
            // SAFETY: The API returned a WLAN-owned list allocation on success.
            let count = unsafe { (*list).dwNumberOfItems };
            if count > 4096 {
                return Err(PlatformError::internal(
                    "Native Wi-Fi network list exceeded the traversal limit",
                ));
            }
            let mut networks = Vec::with_capacity(usize::try_from(count).unwrap_or_default());
            // SAFETY: `Network` is the first item of the variable-size API allocation.
            let first = unsafe { (*list).Network.as_ptr() };
            for index in 0..count {
                // SAFETY: The API guarantees `dwNumberOfItems` contiguous network records.
                let network = unsafe { &*first.add(index as usize) };
                networks.push(decode_network(network, if_index, interface_name)?);
            }
            Ok(networks)
        })();
        // SAFETY: `list` is the WLAN allocation returned above and is released exactly once.
        unsafe { (self.free_memory)(list.cast()) };
        result
    }

    pub(super) fn current_profile(&self, interface: &GUID) -> PlatformResult<Option<String>> {
        self.current_connection(interface).and_then(|connection| {
            connection
                .filter(|attributes| attributes.isState == wlan_interface_state_connected)
                .map(|attributes| fixed_wide(&attributes.strProfileName))
                .transpose()
        })
    }

    pub(super) fn radio_state(&self, interface: &GUID) -> PlatformResult<RadioState> {
        let mut bytes = 0_u32;
        let mut data = ptr::null_mut::<c_void>();
        // SAFETY: All output pointers are writable and successful API memory is released below.
        let code = unsafe {
            (self.query_interface)(
                self.handle,
                interface,
                wlan_intf_opcode_radio_state,
                ptr::null(),
                &raw mut bytes,
                &raw mut data,
                ptr::null_mut(),
            )
        };
        wlan_result("WlanQueryInterface(radio_state)", code)?;
        let result = if data.is_null()
            || usize::try_from(bytes).unwrap_or_default() < size_of::<WLAN_RADIO_STATE>()
        {
            Err(PlatformError::internal(
                "WlanQueryInterface returned a truncated radio state",
            ))
        } else {
            // SAFETY: The size check above covers the complete fixed-size radio-state record.
            let state = unsafe { data.cast::<WLAN_RADIO_STATE>().read_unaligned() };
            if usize::try_from(state.dwNumberOfPhys).unwrap_or(usize::MAX)
                > state.PhyRadioState.len()
            {
                Err(PlatformError::internal(
                    "Native Wi-Fi returned an invalid radio PHY count",
                ))
            } else {
                Ok(classify_radio_state(&state))
            }
        };
        // SAFETY: `data` is the WLAN allocation returned by WlanQueryInterface and is freed once.
        unsafe { (self.free_memory)(data) };
        result
    }

    fn current_connection(
        &self,
        interface: &GUID,
    ) -> PlatformResult<Option<WLAN_CONNECTION_ATTRIBUTES>> {
        let mut bytes = 0_u32;
        let mut data = ptr::null_mut::<c_void>();
        // SAFETY: All output pointers are writable and successful API memory is released below.
        let code = unsafe {
            (self.query_interface)(
                self.handle,
                interface,
                wlan_intf_opcode_current_connection,
                ptr::null(),
                &raw mut bytes,
                &raw mut data,
                ptr::null_mut(),
            )
        };
        if matches!(code, ERROR_NOT_FOUND | ERROR_INVALID_STATE) {
            return Ok(None);
        }
        wlan_result("WlanQueryInterface(current_connection)", code)?;
        let result = if data.is_null()
            || usize::try_from(bytes).unwrap_or_default() < size_of::<WLAN_CONNECTION_ATTRIBUTES>()
        {
            Err(PlatformError::internal(
                "WlanQueryInterface returned a truncated connection record",
            ))
        } else {
            // SAFETY: The size check above covers the complete fixed-size record.
            Ok(Some(unsafe {
                data.cast::<WLAN_CONNECTION_ATTRIBUTES>().read_unaligned()
            }))
        };
        // SAFETY: `data` is the WLAN allocation returned by WlanQueryInterface and is freed once.
        unsafe { (self.free_memory)(data) };
        result
    }

    pub(super) fn connect(&self, interface: &GUID, profile: &str) -> PlatformResult<()> {
        let profile_wide = wide(profile);
        let parameters = WLAN_CONNECTION_PARAMETERS {
            wlanConnectionMode: wlan_connection_mode_profile,
            strProfile: PCWSTR(profile_wide.as_ptr()),
            pDot11Ssid: ptr::null_mut(),
            pDesiredBssidList: ptr::null_mut(),
            dot11BssType: dot11_BSS_type_infrastructure,
            dwFlags: 0,
        };
        // SAFETY: All referenced inputs remain live for the call; reserved is null.
        let code =
            unsafe { (self.connect)(self.handle, interface, &raw const parameters, ptr::null()) };
        wlan_result("WlanConnect", code)?;
        self.wait_for_profile(interface, Some(profile))
    }

    pub(super) fn disconnect(&self, interface: &GUID) -> PlatformResult<()> {
        // SAFETY: The client/interface are valid and reserved is null.
        let code = unsafe { (self.disconnect)(self.handle, interface, ptr::null()) };
        if code == ERROR_INVALID_STATE {
            return Ok(());
        }
        wlan_result("WlanDisconnect", code)?;
        self.wait_for_profile(interface, None)
    }

    fn wait_for_profile(&self, interface: &GUID, desired: Option<&str>) -> PlatformResult<()> {
        let deadline = Instant::now() + CONNECTION_TIMEOUT;
        loop {
            let current = self.current_profile(interface)?;
            let reached = match (current.as_deref(), desired) {
                (None, None) => true,
                (Some(current), Some(desired)) => current.eq_ignore_ascii_case(desired),
                _ => false,
            };
            if reached {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(PlatformError::internal(format!(
                    "Native Wi-Fi did not reach the requested connection state within {} seconds",
                    CONNECTION_TIMEOUT.as_secs()
                )));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

#[derive(Clone, Copy)]
enum ScanEvent {
    Complete,
    Failed(u32),
}

struct ScanContext {
    interface: GUID,
    sender: mpsc::Sender<ScanEvent>,
}

unsafe extern "system" fn scan_notification(data: *mut L2_NOTIFICATION_DATA, context: *mut c_void) {
    if data.is_null() || context.is_null() {
        return;
    }
    // SAFETY: Windows passes back the live context registered by `scan_and_wait` and a complete
    // notification record for the duration of this callback.
    let (data, context) = unsafe { (&*data, &*context.cast::<ScanContext>()) };
    if data.NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM
        || data.InterfaceGuid != context.interface
    {
        return;
    }
    let event = if data.NotificationCode == wlan_notification_acm_scan_complete.0 as u32 {
        Some(ScanEvent::Complete)
    } else if data.NotificationCode == wlan_notification_acm_scan_fail.0 as u32 {
        let reason = if data.dwDataSize >= 4 && !data.pData.is_null() {
            // SAFETY: The scan-failure notification payload begins with a WLAN_REASON_CODE.
            unsafe { data.pData.cast::<u32>().read_unaligned() }
        } else {
            0
        };
        Some(ScanEvent::Failed(reason))
    } else {
        None
    };
    if let Some(event) = event {
        let _ = context.sender.send(event);
    }
}

fn decode_network(
    network: &WLAN_AVAILABLE_NETWORK,
    if_index: u32,
    interface_name: &str,
) -> PlatformResult<WifiNetwork> {
    let (ssid, ssid_hex) = ssid_parts(&network.dot11Ssid)?;
    let profile_name = fixed_wide(&network.strProfileName)?.filter_empty();
    Ok(WifiNetwork {
        interface_if_index: if_index,
        interface_name: interface_name.to_owned(),
        ssid,
        ssid_hex,
        profile_name,
        signal_quality: quality(network.wlanSignalQuality),
        security_enabled: network.bSecurityEnabled.as_bool(),
        authentication: auth_name(network.dot11DefaultAuthAlgorithm),
        cipher: cipher_name(network.dot11DefaultCipherAlgorithm),
        connectable: network.bNetworkConnectable.as_bool(),
        not_connectable_reason: (!network.bNetworkConnectable.as_bool())
            .then_some(network.wlanNotConnectableReason),
        connected: network.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED != 0,
        bss_count: network.uNumberOfBssids,
    })
}

trait EmptyString {
    fn filter_empty(self) -> Option<String>;
}

impl EmptyString for String {
    fn filter_empty(self) -> Option<String> {
        (!self.is_empty()).then_some(self)
    }
}

fn ssid_parts(ssid: &DOT11_SSID) -> PlatformResult<(String, String)> {
    let length = usize::try_from(ssid.uSSIDLength).unwrap_or(usize::MAX);
    if length > ssid.ucSSID.len() {
        return Err(PlatformError::internal(
            "Native Wi-Fi returned an invalid SSID length",
        ));
    }
    let bytes = &ssid.ucSSID[..length];
    let display = String::from_utf8_lossy(bytes).into_owned();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok((display, hex))
}

fn quality(value: u32) -> u8 {
    u8::try_from(value.min(100)).unwrap_or(100)
}

fn interface_state_name(state: WLAN_INTERFACE_STATE) -> &'static str {
    if state == wlan_interface_state_not_ready {
        "not_ready"
    } else if state == wlan_interface_state_connected {
        "connected"
    } else if state == wlan_interface_state_ad_hoc_network_formed {
        "ad_hoc_network_formed"
    } else if state == wlan_interface_state_disconnecting {
        "disconnecting"
    } else if state == wlan_interface_state_disconnected {
        "disconnected"
    } else if state == wlan_interface_state_associating {
        "associating"
    } else if state == wlan_interface_state_discovering {
        "discovering"
    } else if state == wlan_interface_state_authenticating {
        "authenticating"
    } else {
        "unknown"
    }
}

fn effective_interface_state(state: WLAN_INTERFACE_STATE, radio_state: RadioState) -> &'static str {
    if radio_state == RadioState::Off {
        "radio_off"
    } else {
        interface_state_name(state)
    }
}

fn classify_radio_state(state: &WLAN_RADIO_STATE) -> RadioState {
    let count = usize::try_from(state.dwNumberOfPhys).unwrap_or(usize::MAX);
    if count == 0 || count > state.PhyRadioState.len() {
        return RadioState::Unknown;
    }
    let phys = &state.PhyRadioState[..count];
    if phys.iter().any(|phy| {
        phy.dot11SoftwareRadioState == dot11_radio_state_on
            && phy.dot11HardwareRadioState == dot11_radio_state_on
    }) {
        RadioState::On
    } else if phys.iter().all(|phy| {
        phy.dot11SoftwareRadioState == dot11_radio_state_off
            || phy.dot11HardwareRadioState == dot11_radio_state_off
    }) {
        RadioState::Off
    } else {
        RadioState::Unknown
    }
}

fn auth_name(value: DOT11_AUTH_ALGORITHM) -> String {
    let name = if value == DOT11_AUTH_ALGO_80211_OPEN {
        "open"
    } else if value == DOT11_AUTH_ALGO_80211_SHARED_KEY {
        "shared_key"
    } else if value == DOT11_AUTH_ALGO_WPA {
        "wpa_enterprise"
    } else if value == DOT11_AUTH_ALGO_WPA_PSK {
        "wpa_personal"
    } else if value == DOT11_AUTH_ALGO_WPA_NONE {
        "wpa_none"
    } else if value == DOT11_AUTH_ALGO_RSNA {
        "wpa2_enterprise"
    } else if value == DOT11_AUTH_ALGO_RSNA_PSK {
        "wpa2_personal"
    } else if value == DOT11_AUTH_ALGO_WPA3 || value == DOT11_AUTH_ALGO_WPA3_ENT {
        "wpa3_enterprise"
    } else if value == DOT11_AUTH_ALGO_WPA3_SAE {
        "wpa3_personal"
    } else if value == DOT11_AUTH_ALGO_OWE {
        "owe"
    } else {
        return format!("unknown({})", value.0);
    };
    name.to_owned()
}

fn cipher_name(value: DOT11_CIPHER_ALGORITHM) -> String {
    let name = if value == DOT11_CIPHER_ALGO_NONE {
        "none"
    } else if value == DOT11_CIPHER_ALGO_WEP40 {
        "wep40"
    } else if value == DOT11_CIPHER_ALGO_TKIP {
        "tkip"
    } else if value == DOT11_CIPHER_ALGO_CCMP {
        "ccmp"
    } else if value == DOT11_CIPHER_ALGO_WEP104 {
        "wep104"
    } else if value == DOT11_CIPHER_ALGO_BIP {
        "bip"
    } else if value == DOT11_CIPHER_ALGO_GCMP {
        "gcmp"
    } else if value == DOT11_CIPHER_ALGO_GCMP_256 {
        "gcmp_256"
    } else if value == DOT11_CIPHER_ALGO_CCMP_256 {
        "ccmp_256"
    } else if value == DOT11_CIPHER_ALGO_BIP_GMAC_128 {
        "bip_gmac_128"
    } else if value == DOT11_CIPHER_ALGO_BIP_GMAC_256 {
        "bip_gmac_256"
    } else if value == DOT11_CIPHER_ALGO_BIP_CMAC_256 {
        "bip_cmac_256"
    } else if value == DOT11_CIPHER_ALGO_RSN_USE_GROUP {
        "use_group"
    } else if value == DOT11_CIPHER_ALGO_WEP {
        "wep"
    } else {
        return format!("unknown({})", value.0);
    };
    name.to_owned()
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: Both resources are owned by this object and each is released exactly once.
        let _ = unsafe { (self.close_handle)(self.handle, ptr::null()) };
        // SAFETY: The module remains loaded until after all resolved functions are no longer used.
        let _ = unsafe { FreeLibrary(self.library) };
    }
}

pub(super) enum Rollback {
    Profile {
        interface: GUID,
        name: String,
        previous_xml: Option<String>,
    },
    Connection {
        interface: GUID,
        previous_profile: Option<String>,
    },
}

impl Rollback {
    pub(super) fn execute(self) -> PlatformResult<()> {
        let client = Client::open()?;
        match self {
            Self::Profile {
                interface,
                name,
                previous_xml,
            } => match previous_xml {
                Some(xml) => client.set_profile_xml(&interface, &xml),
                None => client.delete_profile(&interface, &name),
            },
            Self::Connection {
                interface,
                previous_profile,
            } => match previous_profile {
                Some(profile) => client.connect(&interface, &profile),
                None => client.disconnect(&interface),
            },
        }
    }
}

pub(super) fn profile_name(profile: &WifiProfile) -> &str {
    profile.name.as_deref().unwrap_or(&profile.ssid)
}

fn profile_xml(profile: &WifiProfile) -> PlatformResult<String> {
    let name = xml_escape(profile_name(profile));
    let ssid = xml_escape(&profile.ssid);
    let connection_mode = if profile.auto_connect {
        "auto"
    } else {
        "manual"
    };
    let hidden = if profile.hidden {
        "<nonBroadcast>true</nonBroadcast>"
    } else {
        ""
    };
    let security = match profile.authentication {
        WifiAuthentication::Open => concat!(
            "<authEncryption>",
            "<authentication>open</authentication>",
            "<encryption>none</encryption>",
            "<useOneX>false</useOneX>",
            "</authEncryption>"
        )
        .to_owned(),
        WifiAuthentication::Wpa2Personal | WifiAuthentication::Wpa3Personal => {
            let secret = resolve_secret(profile.psk.as_ref().ok_or_else(|| {
                PlatformError::invalid_config("secured Wi-Fi profile has no PSK reference")
            })?)?;
            validate_runtime_psk(&secret, profile.authentication)?;
            let authentication = if profile.authentication == WifiAuthentication::Wpa2Personal {
                "WPA2PSK"
            } else {
                "WPA3SAE"
            };
            let key_type = if profile.authentication == WifiAuthentication::Wpa2Personal
                && secret.len() == 64
                && secret.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                "networkKey"
            } else {
                "passPhrase"
            };
            format!(
                "<authEncryption><authentication>{authentication}</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption><sharedKey><keyType>{key_type}</keyType><protected>false</protected><keyMaterial>{}</keyMaterial></sharedKey>",
                xml_escape(&secret)
            )
        }
    };
    Ok(format!(
        "<?xml version=\"1.0\"?><WLANProfile xmlns=\"https://www.microsoft.com/networking/WLAN/profile/v1\"><name>{name}</name><SSIDConfig><SSID><name>{ssid}</name></SSID>{hidden}</SSIDConfig><connectionType>ESS</connectionType><connectionMode>{connection_mode}</connectionMode><autoSwitch>false</autoSwitch><MSM><security>{security}</security></MSM></WLANProfile>"
    ))
}

fn resolve_secret(secret: &SecretRef) -> PlatformResult<String> {
    match secret {
        SecretRef::Literal(value) => Ok(value.clone()),
        SecretRef::Env(name) => std::env::var(name).map_err(|_| {
            PlatformError::not_found(format!(
                "required secret environment variable {name:?} is not set or is not Unicode"
            ))
        }),
    }
}

fn validate_runtime_psk(secret: &str, authentication: WifiAuthentication) -> PlatformResult<()> {
    let hex = secret.len() == 64 && secret.bytes().all(|byte| byte.is_ascii_hexdigit());
    let passphrase =
        (8..=63).contains(&secret.len()) && secret.bytes().all(|byte| (32..=126).contains(&byte));
    if passphrase || (authentication == WifiAuthentication::Wpa2Personal && hex) {
        Ok(())
    } else {
        Err(PlatformError::invalid_config(
            "resolved Wi-Fi PSK must be an 8 to 63 byte printable ASCII passphrase; WPA2 also accepts 64 hexadecimal digits",
        ))
    }
}

fn xml_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
    output
}

fn fixed_wide(value: &[u16]) -> PlatformResult<String> {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16(&value[..end]).map_err(|error| {
        PlatformError::internal(format!("Native Wi-Fi returned invalid UTF-16: {error}"))
    })
}

fn interface_index(guid: &GUID) -> PlatformResult<u32> {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: Both pointers reference complete, initialized GUID/LUID storage for this call.
    let guid_code = unsafe { ConvertInterfaceGuidToLuid(guid, &raw mut luid) };
    wlan_result("ConvertInterfaceGuidToLuid", guid_code.0)?;
    let mut if_index = 0_u32;
    // SAFETY: `luid` was initialized by the successful conversion above and the index output is
    // writable for the duration of this call.
    let index_code = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut if_index) };
    wlan_result("ConvertInterfaceLuidToIndex", index_code.0)?;
    Ok(if_index)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn wlan_result(operation: &str, code: u32) -> PlatformResult<()> {
    if code == 0 {
        return Ok(());
    }
    if code == ERROR_NDIS_DOT11_POWER_STATE_INVALID.0 {
        return Err(PlatformError::unsupported(format!(
            "{operation} is unavailable because the Wi-Fi radio is off; turn on Wi-Fi and retry"
        )));
    }
    let kind = match code {
        ERROR_ACCESS_DENIED => PlatformErrorKind::PermissionDenied,
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => PlatformErrorKind::NotFound,
        ERROR_INVALID_PARAMETER => PlatformErrorKind::InvalidConfig,
        ERROR_SERVICE_NOT_ACTIVE => PlatformErrorKind::Unsupported,
        _ => PlatformErrorKind::Internal,
    };
    Err(PlatformError {
        kind,
        message: format!("{operation} failed with Windows error {code}"),
        rolled_back: false,
    })
}

fn load_symbol<T>(library: HMODULE, name: &'static [u8]) -> PlatformResult<T>
where
    T: Copy,
{
    // SAFETY: The byte strings used by callers are static and NUL-terminated.
    let symbol = unsafe { GetProcAddress(library, PCSTR(name.as_ptr())) }.ok_or_else(|| {
        PlatformError::unsupported(format!(
            "wlanapi.dll does not export {}",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
        ))
    })?;
    if size_of::<T>() != size_of_val(&symbol) {
        return Err(PlatformError::internal(
            "Native Wi-Fi function pointer size mismatch",
        ));
    }
    // SAFETY: The caller supplies the exact ABI-compatible function type for the named export;
    // the size check above prevents representation mismatch.
    Ok(unsafe { transmute_copy_function(symbol) })
}

unsafe fn transmute_copy_function<T: Copy>(symbol: unsafe extern "system" fn() -> isize) -> T {
    // SAFETY: The caller established equal sizes and the named Windows export has the requested
    // `extern system` signature.
    unsafe { std::mem::transmute_copy(&symbol) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::WiFi::{
        WLAN_PHY_RADIO_STATE, WLAN_RADIO_STATE, dot11_radio_state_off, dot11_radio_state_on,
        dot11_radio_state_unknown,
    };

    fn radio_state(software: i32, hardware: i32) -> WLAN_RADIO_STATE {
        let mut state = WLAN_RADIO_STATE {
            dwNumberOfPhys: 1,
            ..Default::default()
        };
        state.PhyRadioState[0] = WLAN_PHY_RADIO_STATE {
            dwPhyIndex: 0,
            dot11SoftwareRadioState: windows::Win32::NetworkManagement::WiFi::DOT11_RADIO_STATE(
                software,
            ),
            dot11HardwareRadioState: windows::Win32::NetworkManagement::WiFi::DOT11_RADIO_STATE(
                hardware,
            ),
        };
        state
    }

    #[test]
    fn radio_state_distinguishes_on_software_off_hardware_off_and_unknown() {
        assert_eq!(
            classify_radio_state(&radio_state(dot11_radio_state_on.0, dot11_radio_state_on.0)),
            RadioState::On
        );
        assert_eq!(
            classify_radio_state(&radio_state(
                dot11_radio_state_off.0,
                dot11_radio_state_on.0
            )),
            RadioState::Off
        );
        assert_eq!(
            classify_radio_state(&radio_state(
                dot11_radio_state_on.0,
                dot11_radio_state_off.0
            )),
            RadioState::Off
        );
        assert_eq!(
            classify_radio_state(&radio_state(
                dot11_radio_state_unknown.0,
                dot11_radio_state_on.0
            )),
            RadioState::Unknown
        );
    }

    #[test]
    fn radio_power_error_is_actionable_and_not_internal() {
        let Err(error) = wlan_result("WlanScan", ERROR_NDIS_DOT11_POWER_STATE_INVALID.0) else {
            panic!("a powered-off radio must not be reported as success");
        };

        assert_eq!(error.kind, PlatformErrorKind::Unsupported);
        assert!(error.message.contains("Wi-Fi radio is off"));
        assert!(error.message.contains("turn on Wi-Fi"));
    }

    #[test]
    fn powered_off_radio_overrides_disconnected_interface_state() {
        assert_eq!(
            effective_interface_state(wlan_interface_state_disconnected, RadioState::Off),
            "radio_off"
        );
        assert_eq!(
            effective_interface_state(wlan_interface_state_disconnected, RadioState::On),
            "disconnected"
        );
    }

    #[test]
    fn profile_xml_escapes_values_and_never_debug_formats_secrets() {
        let profile = WifiProfile {
            selector: None,
            name: Some("name<&".into()),
            ssid: "ssid<&".into(),
            authentication: WifiAuthentication::Wpa2Personal,
            psk: Some(SecretRef::Literal("password<&123".into())),
            auto_connect: true,
            hidden: true,
        };
        let Ok(xml) = profile_xml(&profile) else {
            panic!("test profile should produce XML");
        };
        assert!(xml.contains("<name>name&lt;&amp;</name>"));
        assert!(xml.contains("<name>ssid&lt;&amp;</name>"));
        assert!(xml.contains("<keyMaterial>password&lt;&amp;123</keyMaterial>"));
        assert!(xml.contains("<nonBroadcast>true</nonBroadcast>"));
    }
}
