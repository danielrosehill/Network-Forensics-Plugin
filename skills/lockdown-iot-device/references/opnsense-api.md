# OPNsense API for device forensics and lockdown

Endpoint names checked against `opnsense/core` master on 2026-11-03 (controllers
`Diagnostics/Api/FirewallController.php`, `Diagnostics/Api/PacketCaptureController.php`,
`Firewall/Api/FilterController.php`). Used live on OPNsense 26.7. Older releases may lack
the `firewall/filter` rule API (it shipped as a plugin before it moved into core).

Auth: an API key/secret (System → Access → Users → API keys), HTTP basic auth.

```bash
api() { curl -sk -u "$OPNSENSE_KEY:$OPNSENSE_SECRET" "$OPNSENSE_URL/api/$1" "${@:2}"; }
DEV=192.0.2.50   # the device
```

## State table (who is it talking to right now)

```bash
api diagnostics/firewall/query_states -X POST -d "searchPhrase=$DEV&rowCount=500" \
  | jq -r '.rows[] | [.proto, .src_addr // .src, .dst_addr // .dst, .state // .descr] | @tsv'
```

Print one raw row first (`jq '.rows[0]'`) and adjust field names to your release.
Snapshot it into the forensics folder with the time.

## Packet capture

Payload keys come from the `PacketCapture` model (`interface`, `host`, `port`, `snaplen`,
`count`, `fam`, `protocol`, `promiscuous`, `description`, plus `*_not` flags). `host`
takes a pcap-style host expression.

```bash
JOB=$(api diagnostics/packet_capture/set -X POST -H 'Content-Type: application/json' -d '{
  "packetcapture": {"settings": {
    "interface": "lan", "host": "'"$DEV"' and not net 192.168.1.0/24",
    "snaplen": "1500", "count": "0", "description": "device egress"}}}' | jq -r .uuid)
api diagnostics/packet_capture/start/$JOB -X POST
api diagnostics/packet_capture/search_jobs                # status, size
api diagnostics/packet_capture/stop/$JOB -X POST
api diagnostics/packet_capture/download/$JOB -o captures/$(date +%F)-device.pcap
api diagnostics/packet_capture/remove/$JOB -X POST
```

Use the interface the device's traffic enters on (the LAN or bridge, not WAN, or the
source address is already NATed). If `count: 0` is rejected, set a large count.

## Kill states (after the block rule is in)

```bash
api diagnostics/firewall/kill_states -X POST -d "filter=$DEV"   # -> {"result":"ok","dropped_states":N}
```

## Firewall rules (`firewall/filter`)

Rules created here live in the automation rule set (Firewall → Automation → Filter),
evaluated before interface rules. Back up the config first (System → Configuration →
Backups).

```bash
add() { api firewall/filter/add_rule -X POST -H 'Content-Type: application/json' -d "{\"rule\": $1}"; }
add '{"enabled":"1","action":"pass","interface":"lan","direction":"in","ipprotocol":"inet",
      "protocol":"any","source_net":"'"$DEV"'","destination_net":"lan","description":"device: LAN only","sequence":"10"}'
add '{"enabled":"1","action":"pass","interface":"lan","direction":"in","ipprotocol":"inet",
      "protocol":"UDP","source_net":"'"$DEV"'","destination_net":"(self)","destination_port":"123","description":"device: NTP to router","sequence":"11"}'
add '{"enabled":"1","action":"block","interface":"lan","direction":"in","ipprotocol":"inet",
      "protocol":"any","source_net":"'"$DEV"'","destination_net":"any","log":"1","description":"device: block cloud","sequence":"12"}'
api firewall/filter/apply -X POST
api firewall/filter/search_rule | jq '.rows[] | select(.description|startswith("device:"))'
```

Field values (`lan`, `(self)`, protocol case) vary by release: create one rule in the GUI
and read it back with `get_rule/<uuid>` to see the exact form. Add the same set for
`inet6` if the LAN has IPv6.

## Firewall log (verification, ongoing record)

```bash
api "diagnostics/firewall/log?limit=500" | jq -r --arg d "$DEV" '.[] | select(.src==$d) | [.__timestamp__, .action, .proto // .protoname, .dst, .dstport] | @tsv'
```
