# <Platform> <Model> (`<ONVIF model string>`)

<One line: what it is, where bought, when examined, router.> Everything below was read
off the device or the router unless marked *assumed*.

## Identity

| Field | Value | How obtained |
|---|---|---|
| Platform / firmware vendor | | |
| SoC | | ONVIF model string |
| Wi-Fi chip | (OUI `XX:XX:XX`) | MAC OUI |
| ONVIF Manufacturer / Model | | `GetDeviceInformation` |
| Firmware | | same |
| Serial | **Redacted** if it doubles as the cloud/P2P ID | same |
| Scopes | | `GetScopes` |
| Web UI | | HTTP GET `/` |
| Purchase | store, listing URL, variant, price, date | listing |
| Listing claims vs device | | RTSP probe |
| Phone app | | owner |

## Media

## Listening services (LAN side)

| Port | Service | Notes |
|---|---|---|

## Configuration found on the device

DNS, NTP, accounts, cloud/P2P settings.

## References
