# SSH fingerprint comparison — stock Cowrie vs QPot

A real, reproducible `nmap` scan of three SSH endpoints, captured with
`nmap -p <port> -sV --script ssh2-enum-algos` plus the computed `hasshServer`
(the MD5 over `kex;encryption;mac;compression` that scanners and SIEMs key on).
It shows, concretely, why a stock T-Pot SSH honeypot is trivially fingerprinted
and what QPot does about it.

> Reproduce it yourself: `nmap -p 22 --script ssh2-enum-algos <host>`

| Endpoint | `hasshServer` | Verdict |
|---|---|---|
| **Stock T-Pot Cowrie** | `b74b3746d7c1b9944b2e8db18f062e6f` | Fixed on *every* default Cowrie → trivially blocklisted |
| **QPot Cowrie** (normalized) | `297dcb0fa400afa1aecc6b5008354515` | Off the stock value; legacy/malformed tells removed |
| **QPot HiFi** (real OpenSSH) | `425d29fe50d8e4f5e37efb6e24bcf660` | A genuine OpenSSH 9.2 fingerprint — it *is* OpenSSH |

---

## 1. Stock T-Pot Cowrie — the tells

```
2401/tcp open  ssh  OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (protocol 2.0)
| ssh2-enum-algos:
|   server_host_key_algorithms: (4)
|       ssh-rsa
|       ssh-dss                  <-- OpenSSH disabled DSS by default years ago
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (9)
|       aes128-ctr / aes192-ctr / aes256-ctr
|       aes256-cbc / aes192-cbc / aes128-cbc
|       3des-cbc
|       blowfish-cbc             <-- OpenSSH hasn't offered these by
|       cast128-cbc              <-- default since 7.0 (2015)
|   mac_algorithms: (5)
|       hmac-sha2-512
|       hmac-sha2-384
|       hmac-sha2-56             <-- MALFORMED: no real server sends this
|       hmac-sha1
|       hmac-md5
|   compression_algorithms: (3)
|       zlib@openssh.com / zlib / none
```

`hasshServer = b74b3746d7c1b9944b2e8db18f062e6f` — identical on every default
Cowrie, so a one-line HASSH match (or just "does it offer `blowfish-cbc` /
`hmac-sha2-56`?") flags it instantly and the attacker leaves.

## 2. QPot Cowrie (config-level normalization)

```
2402/tcp open  ssh  OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (protocol 2.0)
| ssh2-enum-algos:
|   server_host_key_algorithms: (3)
|       ssh-rsa / ecdsa-sha2-nistp256 / ssh-ed25519   (ssh-dss gone)
|   encryption_algorithms: (3)
|       aes128-ctr / aes192-ctr / aes256-ctr          (legacy ciphers gone)
|   mac_algorithms: (3)
|       hmac-sha2-256 / hmac-sha2-512 / hmac-sha1      (malformed/md5 gone)
|   compression_algorithms: (2)
|       none / zlib@openssh.com                        (OpenSSH order)
```

`hasshServer = 297dcb0fa400afa1aecc6b5008354515` — a different value from the
blocklisted stock one, and the obvious "this is an emulator" tells are gone.
**Honest limit:** the `kex_algorithms` (`…diffie-hellman-group14-sha1,
ext-info-s`) and `ssh-rsa` host key still come from Cowrie's Python transport
and are not config-controllable, so a determined fingerprinter can still tell
this from real OpenSSH. That's what HiFi mode is for.

## 3. QPot HiFi — real OpenSSH (gap closed)

```
2403/tcp open  ssh  OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
| ssh2-enum-algos:
|   kex_algorithms: (12)
|       sntrup761x25519-sha512 / curve25519-sha256 / …
|       diffie-hellman-group16-sha512 / -group18-sha512 / -group14-sha256
|       kex-strict-s-v00@openssh.com
|   server_host_key_algorithms: (4)
|       ssh-ed25519 / rsa-sha2-512 / rsa-sha2-256 / ecdsa-sha2-nistp256
|   encryption_algorithms: (6)
|       chacha20-poly1305@openssh.com / aes*-ctr / aes*-gcm@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@ / hmac-sha2-256-etm@ / … / hmac-sha2-256 / …
|   compression_algorithms: (2)
|       none / zlib@openssh.com
```

This is a genuine, modern OpenSSH 9.2 `KEXINIT` (post-quantum
`sntrup761x25519`, `chacha20-poly1305`, `aes-gcm`, ETM/umac MACs, `rsa-sha2-*`
host keys, the `kex-strict` mitigation) — **none of which Cowrie's Twisted/conch
transport can emit.** The attacker's handshake is spliced byte-for-byte to a
real OpenSSH daemon, so there is nothing of ours on the wire to fingerprint.
`hasshServer = 425d29fe…` is simply a real OpenSSH HASSH.

---

### How this was produced

```sh
# stock Cowrie, QPot Cowrie, and the HiFi broker on three ports, then:
nmap -p <port> -sV --script ssh2-enum-algos 127.0.0.1
# hasshServer = md5(kex_algos ; enc_s2c ; mac_s2c ; comp_s2c)
```

See `doc/ssh-hifi-proxy.md` for the HiFi architecture and security model, and
the README *Deception & Anti-Fingerprinting* section for the full picture.
