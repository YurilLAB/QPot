# Honeypots

QPot runs 27 honeypots from T-Pot's newest upstream images, `24.04.2`. There
is no T-Pot 25 release. tanner, snare and phpox stay on `24.04.1`, the newest
published for them.

| Honeypot | Emulates |
|---|---|
| `adbhoney` | Android Debug Bridge |
| `beelzebub` | SSH and HTTP answered by an LLM (needs Ollama or an LLM API) |
| `ciscoasa` | Cisco ASA (CVE-2018-0101) |
| `citrixhoneypot` | Citrix NetScaler (CVE-2019-19781) |
| `conpot` | ICS/SCADA devices (Modbus, S7comm, BACnet and more), one device per instance |
| `cowrie` | SSH and Telnet with a medium-interaction shell |
| `ddospot` | UDP amplification (NTP, DNS, SSDP) |
| `dicompot` | DICOM medical imaging |
| `dionaea` | Malware capture (SMB, FTP, MSSQL, SIP) |
| `elasticpot` | Elasticsearch |
| `endlessh` | SSH tarpit |
| `galah` | Web server answered by an LLM (needs Ollama or an LLM API) |
| `go-pot` | HTTP tarpit |
| `h0neytr4p` | Web exploit trap |
| `hellpot` | HTTP tarpit |
| `heralding` | Credential catcher for 12 protocols |
| `honeyaml` | API defined in YAML |
| `ipphoney` | IPP network printer |
| `log4pot` | Log4Shell (CVE-2021-44228) |
| `mailoney` | SMTP |
| `medpot` | HL7 medical messaging |
| `miniprint` | Network printer (JetDirect) |
| `redishoneypot` | Redis |
| `sentrypeer` | SIP and VoIP |
| `ssh-proxy` | High-interaction SSH: real OpenSSH behind the HiFi broker ([HiFi mode](ssh-hifi-proxy.md)) |
| `tanner` | Web application (multi-service) |
| `wordpot` | WordPress |

`qpot honeypot list` shows each one's ports and risk level.

`glutton` and `honeytrap` are left out on purpose: they need host networking
and `NET_ADMIN`, which would break QPot's per-honeypot isolation.

## Turning honeypots on and off

```bash
qpot honeypot enable dionaea    # starts it right away if the instance is running
qpot honeypot disable dionaea
qpot honeypot set cowrie persona=debian-bookworm
```

The same controls are on the web UI's dashboard.

## Honeypots with extra parts

- **tanner** runs as T-Pot does: the snare web front end plus the tanner, API,
  PHP sandbox and Redis containers on an internal network.
- **beelzebub** and **galah** answer attackers with an LLM, and need one set
  before they are enabled:

```bash
qpot honeypot set galah llm_provider=ollama llm_server_url=http://10.0.0.5:11434 llm_model=llama3.1
qpot honeypot set beelzebub llm_provider=ollama llm_model=llama3.1 llm_host=http://10.0.0.5:11434/api/chat
qpot honeypot enable galah
```

How QPot makes each honeypot harder to recognise is in
[deception.md](deception.md).
