# Deception

![QPot anti-fingerprint demo](qpot-fingerprint-demo.gif)

Shared default identities and protocol quirks can reveal a honeypot. QPot varies
identities where its image supports them, preserves selections across restarts,
and tests selected protocol behavior. These measures reduce specific clues;
they do not establish that an emulator is indistinguishable from hardware.

- [Cowrie personas](#cowrie-personas)
- [Cowrie patch layer](#cowrie-patch-layer)
- [Bait files](#bait-files)
- [Connected HiFi environments](#connected-hifi-environments)
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

Within one authenticated SSH TCP connection, shell, exec and SFTP channels now
share a mutable filesystem, runtime hostname and package state. New files,
renames, ownership and permission changes remain visible across those channels;
SFTP uses the same current user/group database. Separate connections start with
fresh visitor state. The stable persona identity is independent of that reset.
Each channel keeps its own working directory, environment and process view.
The generated `/proc` view is read-only to shell and SFTP mutations; trusted
process rendering continues to update it.

`useradd`/`adduser`, `passwd`/`chpasswd`, `su`, `sudo -u`, `id`, `groups`,
`getent`, `chown` and `chgrp` use the virtual account files and process
credentials. Newly managed accounts honor their virtual shadow entry when using
`su`. Bad input, duplicate IDs, private-file access and failed writes return
errors instead of reporting a successful change. This is a
bounded Linux simulation, not a complete operating system or PAM implementation.
Package managers retain their finite emulated catalogs. The OpenWrt curl path
adds/removes the matching official package file bytes and executable visibility;
unsupported OpenWrt package mutations fail rather than installing an unusable
placeholder.
Matching source and license notices are written for operators under
`honeypots/cowrie/licenses/` and are not guest mounts.

## Cowrie patch layer

QPot mounts corrected Cowrie source files read-only over the image's, so
commands answer the way the persona's real tools do. Each change is checked
against the real program.

- **Public-key login.** The image accepts any public key, and it logged a
  client in on the query that only asks whether a key would be accepted,
  before any signature: OpenSSH's client printed "Authenticated" straight
  after "Offering public key". No SSH server does that, so one query showed
  a visitor what it had reached. QPot's Cowrie answers the query with "key
  acceptable" and logs the client in when it then proves it holds the key,
  as sshd does; a signature made with another key is refused. Any key is
  still accepted (`TestCowrieStatefulPublicKey` runs both against the real
  image).
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

The archive names that asset as the instance's Conpot device names itself, so
a visitor who reads the files and then asks the device hears the same thing:

| Device | In the inventory, the handover note and the stored snapshot | Where the device says it |
|---|---|---|
| Substation RTU | Its name (`BRK23-RTU3`), site (`BRK23 Substation`), location and site contact | SNMP `sysName`, `sysLocation`, `sysContact` and the facility name |
| ICCP server | Its domain (`BRK23_ICC`) | The domain and the names of its points |
| Server BMC | Its system name (`node16-ipmi`) | The BMC's system name |
| Smart meter | The server it reports to, by name and address | The meter's own configuration |
| Building controller | The plant room | The BACnet device's location |
| Tank gauge | The station's name and street, and each tank's product and nominal size | The header and tank lines of its inventory report |

A name that can be a host name (the RTU's, the BMC's) also resolves on the
support host, to the asset's address. A PLC, an embedded PC and a HART gateway
report no site name, and the archive gives them none. The asset's address in
the archive stays a made-up private one: where the device is reached from the
internet is not something a support archive would hold.

`qpot honeypot profiles conpot` prints these names for the instance's device,
and the device picker in the web UI shows them as "Presents itself as", so an
operator following a visitor from the support host to the device knows what
both said.

QPot draws these names twice from the instance's site seed, once in the
container that answers and once for the archive. `TestConpotSiteMirror` runs
the container's own code and compares the two for 61 sites; the live profile
test asks the running device (the RTU over SNMP, the gauge for its inventory
report) and compares its answer with what the archive would say.

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

## Connected HiFi environments

HiFi can present an application server with a real PostgreSQL database and an
SSH backup host. `environment=organization` ties their names, addresses, decoy
credentials, host keys, database contents and backups to the same scene. These
are real service relationships within one private cell, distinct from the
reference-only internal hosts in Cowrie's ops bait files.

State lasts for one visitor: every connection from its address, and their
multiplexed channels, while any is open and for `cell_hold_minutes` (default
30) after the last one closes, at most two hours in all. Files, accounts and database writes reflect real changes in that cell.
HiFi app/backup roots are deliberately writable, unlike the static honeypots'
read-only roots. This allows ordinary OS consequences for permissions, accounts
and tools. A dedicated sensor VM and suitable isolation/storage limits remain
necessary; log cleanup is not a portable hard quota on writable image layers.
The app, database and backup reset together before the slot serves another
visitor. The broker knows a visitor only by its address: one that changes
address starts afresh, and `cell_hold_minutes=0` resets after every
connection.
Logs and session evidence follow QPot's retention policy independently of the
reset. Failed reset/health checks keep the cell out of the pool.

Standalone remains the default. The connected mode uses three decoy containers
per backend slot, with per-container resource limits, private per-slot bridges
and a host cell guard. The broker listens only on its ingress network; decoys
cannot use its private interface to obtain a different cell. Host, LAN,
management, unrelated cells and Internet destinations remain outside the scene.
SSH forwarding remains disabled. Effective containment must be validated on a
host that can apply the production guard; generated configuration is not enough.

This development feature requires current HiFi images built from the same
checkout, selected with `image_source=local`. Old published images cannot be
silently substituted. The dashboard explains the environment, image source,
connection lifetime and container cost; the CLI accepts the same settings.
See [HiFi deployment](ssh-hifi-proxy.md#5-deployment) for build commands and
operational limits. It does not add a new public sensor or change release pins.

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
- **HiFi credentials.** HiFi uses real Debian 12/OpenSSH backends. Credential
  and hostname selection does not make their userland or kernel another OS.
  The optional organization environment uses coherent application/database/
  backup roles, rather than presenting an arbitrary credential persona as a
  different operating system.

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

Conpot's Modbus server closes a connection at once when a client sends the
five bytes `quit.`, which no PLC does and which is easy to try. QPot's
mounted server treats them as the start of a frame header like any other
bytes.

The image's RTU profile gives the device an SNMP name and registers only its
contact and location, so a request for `sysName` was answered with an empty
string by a device that answers the other two. QPot's site step registers the
name too: the RTU now answers with its station's name (`BRK23-RTU3`), the one
the support archive carries.

The existing Modbus register map remains compatible with earlier QPot versions;
its unusual raw wire addresses are not presented as a verified M340 process map.
The Beckhoff OPC UA server's build date and advertised internal endpoints
still need product-specific comparison. IEC 104/DNP3 session
and point tests do not implement a complete station, select/operate process or
programming environment. Standard ports may be remapped by Docker/NAT. The
support-host exports use device ports and distinct private asset references, not
the deployment's published endpoints.

### One site per instance

The image draws addresses, MACs and serial numbers per install. Other things
a visitor reads were the same on every install, and so named the image:

| Profile | The same everywhere | Now per instance |
|---|---|---|
| Substation RTU | SNMP name `DE-BER01`, location `BER01, T2E`, contact `Corporate IT`, facility `BER01 Substation` | One station code for all four (for example `BRK23-RTU3`, `BRK23, T2E`, `BRK23 Substation`) and a contact |
| Substation RTU, DNP3 | Two binary inputs reading off and on, two analog inputs reading 25 and 100 | The site's own four values. They do not move while the instance runs. |
| ICCP server | Domain `BER01_ICC` and points named `BER01_…` | The same kind of station code |
| Server BMC | System name `DoE` | A host name such as `node16-ipmi` |
| Smart meter | Reporting server `pwr_ctrl_mgmt01.int.local` at `10.232.15.242` | A server name and a private address |
| Building controller | Location `Technikzentrale` | A plant room name |

QPot replaces them after the image has rendered the profile, from the
instance's site seed. QPot derives that seed from the instance's own
deception seed and passes it to Conpot when it starts it, so nothing inside
the container has to be saved for the site to stay the same: every start of
an instance shows the same plant, a new container or an empty state folder
included, and no two instances show the same one. The values the image draws
itself on a first start (addresses, MACs, serial numbers) are drawn from the
same seed, and so are the PLC's process and the tank gauge's station and
tanks.

The state folder is written by the container, so what is in it decides
nothing about the site and can never keep the instance from starting:

- The seed is not read from it. A `qpot_site.json` there (an unreleased
  version of the site step kept its seed in that file) is ignored.
- The image's identity file of a template (`<template>.json`, which 1.1.2
  and earlier kept) is read without following a link, never from anything
  but a small regular file, and each value in it is used only if the
  image's own generator could have drawn it (a private address, a MAC with
  the template's vendor prefix, the right number of digits, and so on).
  Anything else is ignored and drawn from the seed instead; a damaged file
  no longer stops Conpot. So an instance that ran 1.1.2 keeps the
  addresses, MACs and serial numbers its visitors saw.
- The tank gauge keeps the labels visitors set and where its model stands
  (`qpot_gauge.json`). Labels that are not a gauge's (too long, not plain
  text, no tank number) are dropped, and the model is never replayed from
  further back than 30 days: a gauge without a midnight kept in the last 30
  days starts its history again ten days back.

Conpot refuses to start without the seed QPot passes, rather than show a
plant made up for one start.

Each value the image is known to carry must be found where it is expected:
if one is not, the image has changed and the honeypot does not start with
unreviewed values. `TestConpotSiteIdentity`, `TestConpotSiteSeed` and the
live profile test cover it; the live test also starts each profile again
with an empty state folder (the same device) and as another instance (a
different one).

Left as the image has them, because they are what the real product reports
on every unit: the Modicon's vendor, product code and revision, the DNP3
product code, and the TwinCAT runtime's device name.

### The tank gauge

The image's tank gauge (`guardian_ast`, a Veeder-Root TLS-350) is the most
written-about honeypot there is, and the image's code shows every published
sign: replies without the SOH and ETX bytes a gauge frames them with, a date
like `11/12/2026 10:15` where a gauge prints `NOV 12, 2026 10:15 AM`, readings
drawn at random when it starts that never change afterwards, a temperature
compensated volume unrelated to temperature, an ullage unrelated to volume,
one tank always in high water alarm, and an error for every command but
five.

QPot replaces that server (a read-only mount over the image's file, tied to
its hash). What it does instead:

- **One model of the site gives every report its numbers.** Each tank has a
  size and a shape. Fuel is sold through the day and less at night, a
  delivery refills a tank that runs low and appears in the delivery report,
  ullage is what is left of the tank, height follows from volume and the
  tank's diameter, and temperature compensated volume from volume and
  temperature. The model depends only on the instance's seed and the clock:
  two looks an hour apart differ as a real site's do, and a restart changes
  nothing.
- **Reports are laid out as a gauge lays them out.** The inventory report
  reproduces a published capture of a real gauge column for column
  (`TestConpotTankGaugeLooksLikeAGauge` rebuilds that capture's row and date
  line byte for byte). The delivery, leak test, shift, status and label
  reports follow the wording of the vendor's serial interface manual.
- **Per instance:** the station's name and street, three or four tanks and
  their products, sizes and sales, and a clock a few minutes off. The header
  names no town, because QPot does not know where the sensor is hosted and a
  header must not contradict it.
- **A label a visitor sets stays set**, across connections and restarts, as
  on a real gauge. The image forgot it when the connection closed.
- **A command the gauge does not know** gets `9999FF1B` between SOH and ETX.
  Tank numbers work (`I20102` is tank 2), and so does the software revision
  report scanners ask for (`I90200`).

What is not verified against a real gauge: the line ends (carriage return and
line feed are assumed; no public capture shows the bytes), the exact column
positions of the reports taken from the manual, whose samples are typeset,
and commands outside inventory, delivery, leak test, shift, status, labels
and software revision, which get the not-understood reply. Units are US
gallons, inches and degrees Fahrenheit, as on the captures; a metric site is
not offered.

### The PLC's process values

The image's Beckhoff profile has four OPC UA variables, and on every install
they read 21.4 degrees, 3.82 bar, pump running, batch 1187, for as long as
the container runs. A PLC's program writes its variables on every cycle.

QPot mounts the image's OPC UA server with one change (read-only, tied to
the file's hash): the four variables come from a small model of a batch
process. A pump runs for part of every batch, the pressure follows the pump
within seconds, the temperature follows both slowly and moves a little over
the day, and the batch counter counts batches since the plant was
commissioned. What a batch lasts (18 to 55 minutes), how long the pump runs,
the pressures, the temperature and the commissioning date are drawn from the
instance's seed. The readings depend only on the seed and the clock, so a
restart continues them, and they are written once a second with their time:
a value a visitor writes is replaced by the next cycle, as a running program
would replace it. The batch counter is a 32-bit integer, as TwinCAT's is,
where the image served 64 bits.

`TestConpotOPCUAProcess` checks the model (nothing jumps, the pressure
follows the pump, 300 seeds give 300 plants, none reads the image's values)
and the live profile test reads the variables from the running image twice,
writes one in between and expects the program's value back.

What this is not: a TwinCAT address space. A real server shows the PLC's
whole symbol tree, its types and its device state; this one shows one folder
with four variables.

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
honeypot, passes the attacker straight to real OpenSSH backends. Standalone
servers have no outbound access; connected mode permits only its controlled
cell peers. The entire cell is recreated after each visitor. Enable it with
`qpot setup --profile hifi` or `qpot honeypot enable ssh-proxy`.

- [ssh-hifi-proxy.md](ssh-hifi-proxy.md): how HiFi mode works.
- [fingerprint-comparison.md](fingerprint-comparison.md): an `nmap` SSH
  fingerprint of stock Cowrie, QPot and real OpenSSH, side by side.
