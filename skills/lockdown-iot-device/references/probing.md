# Probing the device

## Network identity

```bash
sudo nmap -sn <dev>                      # up + MAC + OUI vendor
nmap -sT -sV -p 1-10000 <dev>            # TCP services
sudo nmap -sU -p 53,123,1900,3702,5353,6668,8765,32100,32108 <dev>
```

## ONVIF

Common ONVIF ports: 80, 8000, 8080, 8899. `GetSystemDateAndTime` usually answers
without auth, which confirms the port:

```bash
curl -s -H 'Content-Type: application/soap+xml' http://<dev>:8899/onvif/device_service -d \
'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
```

Authenticated queries (WS-Security digest) are easiest via `onvif-zeep`:

```bash
uv run --with onvif-zeep python - <<'PY'
import os
from onvif import ONVIFCamera
c = ONVIFCamera(os.environ["DEV"], int(os.environ.get("ONVIF_PORT", 8899)), os.environ["DEV_USER"], os.environ["DEV_PASS"])
d = c.devicemgmt
for name in ["GetDeviceInformation", "GetScopes", "GetNetworkInterfaces", "GetDNS", "GetNTP"]:
    try: print(name, getattr(d, name)())
    except Exception as e: print(name, "ERR", e)
PY
```

Read: `Model` (often names the SoC, e.g. `IPC_GK7205V500_...`), `FirmwareVersion`
(format identifies the firmware house), `SerialNumber` (often the cloud/P2P ID: redact),
scopes (`location/country/...`), configured DNS (look for a hard-coded public resolver
next to the DHCP one) and NTP server.

## Media

```bash
ffprobe -v error -rtsp_transport tcp -show_streams rtsp://<user>:<pw>@<dev>:554/<path>
```

Record codec, resolution, audio. Try a second path to see whether a substream exists or
the path is ignored.

## Web UI

```bash
curl -s http://<dev>/ -o ui.html; grep -oE 'src="[^"]+\.js"' ui.html
curl -s http://<dev>/<script>.js | grep -oE '[a-zA-Z0-9.-]+\.(com|cn|net|io)' | sort -u
```

Plug-in and download URLs often name the vendor's cloud brand.
