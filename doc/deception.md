# Deception

![QPot anti-fingerprint demo](qpot-fingerprint-demo.gif)

A stock T-Pot install is easy to recognise, because every install is
identical. QPot gives each instance a distinct, self-consistent identity, and
keeps it across restarts so a returning attacker meets the same machine.

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

Every secret in them is a planted canary, so using one raises an alert. Turn
them off with `qpot honeypot set cowrie bait=off`. Details:
[canary.md](canary.md#canaries-planted-in-the-honeypots).

## Other honeypots

- **Dionaea.** Every T-Pot dionaea answered SMB as `ADFS` in `DACH`, and its
  RPC and MSSQL services as `HOMEUSER-3AF6FE`. Each instance now answers
  everywhere as one Windows 7 machine of its own (`<USER>-PC`, or `WIN-` and
  11 characters) in `WORKGROUP`.
- **Conpot.** Conpot emulates one device from the T-Pot image, picked per
  instance:
  - a Siemens substation RTU (IEC 104, DNP3, SNMP);
  - a Veeder-Root tank gauge;
  - a Supermicro BMC;
  - a Kamstrup meter;
  - a Beckhoff PLC (ADS, OPC UA);
  - a LOYTEC building controller (BACnet, KNX);
  - an Emerson HART gateway;
  - an ICCP server;
  - a Modicon PLC (Modbus).

  It publishes only that device's ports, and keeps the device's address, MAC,
  serials and PINs across restarts. The image's multi-protocol `default`
  template, the same on every install, is never used. Pin one with
  `qpot honeypot set conpot template=<id>`.
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
