# Deception

![QPot anti-fingerprint demo](qpot-fingerprint-demo.gif)

Shared default identities and protocol quirks can reveal a honeypot. QPot varies
identities where its image supports them, preserves selections across restarts,
and tests selected protocol behavior. These measures reduce specific clues;
they do not establish that an emulator is indistinguishable from hardware.

- [Cowrie personas](#cowrie-personas)
- [Cowrie patch layer](#cowrie-patch-layer)
- [Bait files](#bait-files)
- [Other honeypots](#other-honeypots)
- [No giveaways](#no-giveaways)
- [Limits and HiFi mode](#limits-and-hifi-mode)

## Cowrie personas

Cowrie runs as one of the persona engine's machines: Ubuntu 24.04 and 22.04,
Debian 13 and 12, RHEL 9, CentOS 7, Raspberry Pi OS, a GPU server, and routers,
NAS boxes and an IP camera. The engine builds the whole box from the persona:

- the OpenSSH release, with that release's key-exchange and host-key lists;
- `uname` and `/proc`, and a process table whose start times match the uptime;
- `lscpu`, `lspci`, `mount` and `df`;
- the network behind `ip`, `ss` and `netstat`;
- the packages behind `dpkg` and `rpm`;
- the units behind `systemctl`, and the `sudo` rules.

QPot picks a server persona per instance and keeps the identity it draws (host
name, patch level, boot time, addresses) for a year by default.

```bash
qpot honeypot set cowrie persona=debian-bookworm   # optional; picked per instance if unset
qpot honeypot set cowrie persona_rotation=30       # days to keep the drawn identity (0-365, default 365)
```

## Cowrie patch layer

QPot mounts corrected Cowrie source files read-only over the image's, so
commands answer the way the persona's real tools do. Each change is checked
against the real program.

- **Terminal.** The shell writes what bash 5.2's readline or BusyBox's `ash`
  writes, byte for byte. Before, the prompt came with an `ESC[4h` insert-mode
  switch and Ctrl-C printed no `^C`.
- **Network tools.**
  - `ping` is the persona's iputils or BusyBox ping, with real statistics.
  - `curl` and `wget` answer as the persona's releases do. They connect only to
    the address they checked, and never to the host's own network.
  - `scp` and `sftp` behave like OpenSSH and log the key they would offer.
- **File tools.** `ls` matches GNU coreutils or BusyBox, including column
  layout, link counts and dates. `stat` and `gzip -l`/`-t` match the real
  tools too.
- **Shell.** `$BASH_VERSION` and `help` match the persona's bash, `exit` says
  `logout`, and `hostname -f` no longer renames the host.
- **Common programs** that used to end in "Exec format error" now work:
  `arch`, `timeout`, `setsid`, `nice`, `basename`, `dirname`,
  `md5sum`/`sha*sum`, `mktemp`, `tty`, `sync`, `printenv` and `expr`.

## Bait files

Server personas carry the files an intruder expects on an operations box:

- an SSH key and shell histories;
- a backup script;
- AWS and git credentials;
- a database dump.

Choose the files with `cowrie bait_profile=ops` (the default) or
`cowrie bait_profile=industrial`. Industrial support archives contain a parseable
inventory, communication exports, maintenance notes and dated compressed snapshots
under `/srv/ot`, plus a maintenance SSH identity and archive credentials. They
belong to a Linux support host and reference a separate asset using the selected
Conpot device model and protocols. They do not install a Windows engineering
runtime, add a filesystem to a PLC, or claim a live connection to Conpot.

```bash
qpot honeypot set cowrie persona=debian-bookworm bait_profile=industrial
```

The archive is rendered when Cowrie starts. After changing the referenced device,
reapply `bait_profile=industrial` to recreate Cowrie and refresh it. The credentials
remain stable while the device reference changes. `bait_profile=` restores ops;
`bait=off` stops planting either profile. Previously exposed credentials remain
watched and are labelled as historical in the canary UI. Reading a file alone is
not an alert: QPot must observe reuse of a watched value. Details:
[canary.md](canary.md#canaries-planted-in-the-honeypots).

## Other honeypots

- **Dionaea.** Every T-Pot dionaea answered SMB as `ADFS` in `DACH`, and its
  RPC and MSSQL services as `HOMEUSER-3AF6FE`. Each instance now answers
  everywhere as one Windows 7 machine of its own (`<USER>-PC`, or `WIN-` and
  11 characters) in `WORKGROUP`.
- **Conpot.** Conpot emulates one device from the T-Pot image, picked per
  instance and recorded with a profile version:
  - a Siemens substation RTU (IEC 104, DNP3, SNMP);
  - a Veeder-Root tank gauge;
  - a Supermicro BMC;
  - a Kamstrup meter;
  - a Beckhoff PLC (ADS, OPC UA);
  - a LOYTEC building controller (BACnet, KNX);
  - an Emerson HART gateway;
  - an ICCP server;
  - a Modicon PLC (Modbus).

  It publishes only that device's ports and persists the generated identity
  fields supported by that template (addresses, MACs, serials or PINs where
  available). The Modbus template exposes manufacturer/product/firmware objects;
  it does not generate a serial number or emulate a PLC program. The image's multi-protocol `default`
  template, the same on every install, is never used. Pin one with
  `qpot honeypot set conpot template=<id>`. Explore device descriptions and
  protocols with `qpot honeypot profiles conpot` or the dashboard's Industrial
  control systems card. The automatic choice survives catalog updates; clearing
  a pin restores that saved choice. These are device protocol emulations, not
  complete physical processes or industrial sites. The Modbus profile also uses
  read-only patches of the immutable image's Modbus modules. Identification
  requests honor object/read-code semantics; unsupported serial-only diagnostics
  return an exception. Segmented frames remain valid within a bounded request
  time budget, non-Modbus protocol IDs are discarded before executing a request,
  and length limits remain enforced. Tests use raw packets and an independent
  Modbus client; full assertions run once after separate readiness checks.
- **Heralding.** Every service answers as the machine its persona describes,
  an Ubuntu, Debian, RHEL or Windows Server host. The FTP, SSH, SMTP, POP3 and
  IMAP greetings, the web server header and the certificate subject all agree. The image's
  stock greetings (`OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8`, "Microsoft FTP Server",
  an Exchange SMTP banner) are removed.
- **ADB.** adbhoney introduces itself as one Android 8 phone picked per
  instance, such as a Pixel 2, Mi A1 or Galaxy S9, the way a real adbd does,
  instead of the stock banner every ADBHoney install sends. Fetching URLs from attacker
  commands is off: the image's downloader would request any address, including
  ones on your own network.
- **HiFi credential personas.** HiFi mode's real-OpenSSH backends accept a
  persona's believable weak passwords (30 personas, such as a corporate Ubuntu
  host, a database server or a Proxmox host) under a matching host name.

## Refrigeration supervisor

The native `refrigeration` honeypot presents one legacy AK-SM 800A / StoreView
management generation, with documented XML requests, original browser assets
and coherent virtual retail or plasma storage. Device identity, controls, alarms,
history and maintenance exports share its state. It is built locally from the
sources bundled into QPot and does not run vendor firmware. Details and
limitations: [refrigeration.md](refrigeration.md).

## Industrial fidelity and its limits

An attacker can compare service identity, supported function codes, object lists,
protocol errors, session state, timing and network endpoints. A believable file
name cannot repair a contradictory protocol response. Identification, read/write,
negative, fragmented-frame and restart tests therefore complement the profile
picker. These checks establish selected behavior, not complete vendor firmware
conformance or compatibility with every engineering tool.

The existing Modbus register map remains compatible with earlier QPot versions;
its unusual raw wire addresses are not presented as a verified M340 process map.
Beckhoff OPC UA values are static; its build date, state dynamics and advertised
internal endpoints still need product-specific comparison. IEC 104/DNP3 session
and point tests do not implement a complete station, select/operate process or
programming environment. Standard ports may be remapped by Docker/NAT. The
support-host exports use device ports and distinct private asset references, not
the deployment's published endpoints.

The building controller's BACnet Who-Is and Who-Has discovery respects paired,
inclusive device-instance limits. Out-of-range or incomplete discovery ranges
do not produce an identity reply. The read-only patch is tied to the pinned
Conpot module, with packet tests across startup, restart and recreation.

Research informing these checks includes [Vetterl and Clayton (WOOT18)](https://www.usenix.org/conference/woot18/presentation/vetterl)
and [Gotta Catch 'em All](https://dl.acm.org/doi/full/10.1145/3584976).
Their published Conpot signatures concern older revisions; they are not proof
that the same signature occurs in this pinned image. Protocol requirements come
from the [Modbus application specification](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf),
[official Nmap identification documentation](https://nmap.org/nsedoc/scripts/modbus-discover.html),
[OPC UA ServerStatus/BuildInfo](https://reference.opcfoundation.org/specs/OPC-10000-5/8.3.2)
and [Beckhoff ADS ReadDeviceInfo](https://infosys.beckhoff.com/content/1033/tcadscommon/12440288395.html).
[Beckhoff's engineering file table](https://infosys.beckhoff.com/content/1033/tc3_sourcecontrol/18014398915785483.html)
helps distinguish real engineering project files from arbitrary files merely
renamed with a vendor extension. QPot's industrial exports are documented local
CSV/JSON/text formats, rather than fabricated importable vendor projects.

## No giveaways

Container environments contain no `qpot`, `tpot` or `honeypot` strings and no
stealth settings: an intruder who reads `/proc/1/environ` finds nothing that
names a honeypot. The config files QPot mounts use the images' own formats and
cannot be reached from an attacker's session.

## Limits and HiFi mode

Cowrie's cipher and MAC lists and its packet handling come from its Python SSH
stack, so a determined packet-level fingerprinter can still tell it from real
OpenSSH.

**HiFi mode** closes that gap. A transparent TCP broker, the `ssh-proxy`
honeypot, passes the attacker straight to real OpenSSH backends on a network with no outbound
access, and each backend is recreated after every session. Enable it with
`qpot setup --profile hifi` or `qpot honeypot enable ssh-proxy`.

- [ssh-hifi-proxy.md](ssh-hifi-proxy.md): how HiFi mode works.
- [fingerprint-comparison.md](fingerprint-comparison.md): an `nmap` SSH
  fingerprint of stock Cowrie, QPot and real OpenSSH, side by side.
