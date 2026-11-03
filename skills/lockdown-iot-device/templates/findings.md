# How the <model> reaches the internet (<YYYY-MM-DD>)

Router: <type + version>. Device on <LAN/VLAN>, DHCP reservation, port-forwards: <none>,
UPnP: <state, confirmed or assumed>.

## Method

1. State table for `<dev>`: <command/API>, snapshot at <time>.
2. Packet capture: interface <if>, filter `host <dev> and not net <lan>`, snaplen 1500,
   <start>–<end>. Actions during it, with times: <app on mobile data, live view, PTZ, ...>.
3. `whois` on each remote IP.
4. Device-side: <ONVIF queries, nmap>.

## Outbound flows

| Proto | Destination | Port | State | Owner (whois) | Reading |
|---|---|---|---|---|---|

## DNS names and TLS SNI (from the capture)

## What this means

## Remediation applied (<date>)

Rules (order, description), states killed (count), IPv6/UPnP handling.

## Verification (<date>)

State table after: <only LAN flows?>. Firewall log: <blocked destinations, retry rate>.
Local use: <NVR streams?>. App off-LAN: <fails?>.

## Open questions
