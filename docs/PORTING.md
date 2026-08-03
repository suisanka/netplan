# Porting matrix

This matrix defines the P0 capability boundary.

| Capability | P0 contract | Initial backend |
| --- | --- | --- |
| Adapter inventory | Native typed discovery | Windows IP Helper API |
| DHCP/static IPv4 | Validate and plan | Live apply gated pending Windows tests |
| DNS, gateway, WINS | Validate and plan | Live apply gated pending Windows tests |
| Adapter selection | Index, name, GUID, MAC, description | Implemented in shared planner |
| MAC override | Validate and plan | Capability-gated |
| Wi-Fi | Profiles, scan/connect/disconnect contract | Capability-gated by WLAN API/service |
| SMB shares | Share definitions and account references | Capability-gated by LanmanServer |
| SMB mappings | UNC mappings and credentials | Capability-gated by MPR/workstation |
| Machine identity | Computer name, workgroup, DNS suffix | Capability-gated |
| Firewall/services | Desired state contract | Capability-gated |
| Driver install/restart | Explicit operation contract | Deferred after P0 safety testing |
| Hooks | Executable plus argument array, never shell text | Capability-gated |

Stock WinPE and modified PE images expose different subsets. Unsupported operations
must return a typed `Unsupported` error rather than silently succeeding.
