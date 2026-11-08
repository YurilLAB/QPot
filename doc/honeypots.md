# Honeypots

QPot offers 28 honeypots, including the native refrigeration supervisor and
HiFi SSH broker. The T-Pot services use upstream `24.04.2`; tanner, snare and
phpox stay on `24.04.1`, the newest published for them. There is no T-Pot 25 release.

| Honeypot | Emulates |
|---|---|
| `adbhoney` | Android Debug Bridge |
| `beelzebub` | SSH and HTTP answered by an LLM (needs Ollama or an LLM API) |
| `ciscoasa` | Cisco ASA (CVE-2018-0101) |
| `citrixhoneypot` | Citrix NetScaler (CVE-2019-19781) |
| `conpot` | Industrial device profiles (Modbus, IEC 104, OPC UA and more), one device per instance |
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
| `refrigeration` | Legacy refrigeration supervisor with XML/web management and virtual retail or plasma cold storage ([details](refrigeration.md)) |
| `sentrypeer` | SIP and VoIP |
| `ssh-proxy` | High-interaction SSH: real OpenSSH behind the HiFi broker ([HiFi mode](ssh-hifi-proxy.md)) |
| `tanner` | Web application (multi-service) |
| `wordpot` | WordPress |

`qpot honeypot list` shows each one's ports and risk level.

`glutton` and `honeytrap` are left out on purpose: they need host networking
and `NET_ADMIN`, which would break QPot's per-honeypot isolation.

## Industrial control systems

The dashboard has an **Industrial control systems** card. Choose a device to
see its model, protocols, device ports and simulation limits before saving.
The picker uses the same supported profile IDs as the CLI:

```bash
qpot honeypot profiles conpot              # devices, protocols and limitations
qpot honeypot set conpot template=plc_modbus
qpot honeypot enable conpot
qpot honeypot list                         # configured host ports, not a reachability check
```

`plc_modbus` is a Schneider Modicon M340 PLC (Modbus/TCP); `IEC104` is a
substation RTU (IEC 104, DNP3 and SNMP); `beckhoff_cx` is an industrial
controller with OPC UA and ADS. The catalog also distinguishes related meters,
tank gauges, building controllers and server management devices. A Siemens
device name does not imply S7comm support: the stock multi-protocol `default`
template is not offered.

For a **new** instance, `qpot setup --profile industrial` enables only Conpot
and explicitly selects the Modbus PLC. Existing instance settings are kept.
Choose a different device later through the dashboard or `honeypot set`.

Device ports such as Modbus TCP 502 are inside the container. Automatic port
allocation can publish them on different host ports; inspect the configured
mappings before connecting. Changing a running device recreates Conpot, so
existing protocol sessions disconnect. Saving while it is off does not enable
it. A saved change that fails to start is reported as a failure, not success.

The automatic choice is saved with a profile version and survives catalog
reordering or expansion. `template=` clears an explicit pin and returns to
that saved automatic choice. This release selects one emulated device per
instance; it does not add an HMI or a coordinated PLC/RTU industrial site.

## Refrigeration and cold storage

`qpot setup --profile refrigeration` creates a new supervisor-only instance.
For an existing instance, enable `refrigeration` and choose `site_profile=retail`
or `site_profile=plasma` in its settings. The dashboard has a dedicated card and
a link to the decoy console. The image is built locally from bundled Go sources,
so first start needs access to the pinned builder image. No vendor firmware or
real equipment is run. See [refrigeration.md](refrigeration.md) for the XML subset,
accounts, files, canaries, persistence and simulation limits.

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
