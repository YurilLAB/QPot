package instance

// Working files for the two personas that are no ops box. A GPU machine with
// Ollama and Jupyter is somebody's training box: its user keeps an experiment
// tracker's key, a notebook server's token and a project with its .env. A
// Raspberry Pi on a home or office network keeps the Wi-Fi it was set up on,
// a dynamic DNS updater and a copy job to the NAS. Each got the database
// backup job of a server before, which neither would run.
//
// The same rules as bait.go: only what the persona's own programs can use
// (bash, curl, ssh, python3), names and secrets drawn from the instance's
// seed, every secret a canary, times between installation and boot. A path
// the persona already has stays the persona's: the GPU persona brings its own
// shell history, ~/.env and Hugging Face token, and the plan adds around them.

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/qpot/qpot/internal/canary"
)

// baitSceneKind says which working files a persona carries with
// bait_profile=ops: a server's, a GPU workstation's or a Raspberry Pi's.
func baitSceneKind(p tpotCowriePersona) string {
	switch {
	case p.ID == "gpu-ubuntu":
		return "workstation"
	case p.Family == "raspios":
		return "pi"
	}
	return "server"
}

// userKey writes the login user's SSH key pair, a config that names the
// hosts it is for and their known_hosts lines, and plants the key.
func (s *baitScene) userKey(comment, what string, at float64, hosts ...baitHostInfo) {
	key := s.d.Ed25519Key("user-key")
	blob := canary.Ed25519PublicBlob(key.Public().(ed25519.PublicKey))
	check := binary.BigEndian.Uint32(s.d.Bytes("user-key-check", 4))
	dir := s.home + "/.ssh"
	s.dir(dir, s.user, 0o700, 0.001)
	s.file(baitFile{Path: dir + "/id_ed25519", Owner: s.user, Mode: 0o600, At: at,
		Text: string(canary.MarshalEd25519PrivateKey(key, comment, check))})
	pub := canary.AuthorizedKey(blob, comment)
	s.file(baitFile{Path: dir + "/id_ed25519.pub", Owner: s.user, Mode: 0o644, At: at, Text: pub + "\n"})
	var cfg, known strings.Builder
	for i, h := range hosts {
		fmt.Fprintf(&cfg, "Host %s\n    HostName %s\n    User %s\n    IdentityFile ~/.ssh/id_ed25519\n\n", h.Alias, h.FQDN, h.User)
		line := canary.AuthorizedKey(canary.Ed25519PublicBlob(s.d.Ed25519Key("hostkey-"+h.FQDN).Public().(ed25519.PublicKey)), "")
		known.WriteString(canary.HashKnownHost(s.d.Bytes(fmt.Sprintf("user-kh-salt-%d", i), 20), h.FQDN) + " " + line + "\n")
		s.plan.Hosts = append(s.plan.Hosts, baitHost{Names: []string{h.Alias, h.FQDN, h.IP}, IP: h.IP})
	}
	cfg.WriteString("Host *\n    ServerAliveInterval 60\n")
	s.file(baitFile{Path: dir + "/config", Owner: s.user, Mode: 0o644, At: at + 0.01, Text: cfg.String()})
	s.file(baitFile{Path: dir + "/known_hosts", Owner: s.user, Mode: 0o644, At: at + 0.02, InPlace: true, Text: known.String()})
	s.plant(&canary.Canary{ID: s.d.ID("user-key"), Kind: canary.KindSSHKey, Name: "cowrie bait: " + s.user + " SSH key",
		PublicKey: pub, Values: []string{strings.Fields(pub)[1], canary.MD5Fingerprint(blob)},
		Memo: s.memo("an SSH key for "+what+", trips when it is offered in a login", dir+"/id_ed25519")})
}

// notebookCell is a cell of a Jupyter notebook (nbformat 4).
type notebookCell struct {
	CellType string         `json:"cell_type"`
	Count    *int           `json:"execution_count,omitempty"`
	Metadata map[string]any `json:"metadata"`
	Outputs  []any          `json:"outputs,omitempty"`
	Source   []string       `json:"source"`
}

// notebook renders code cells (a cell that starts with "# " alone on its
// first line of one line is a markdown heading) as a notebook file.
func notebook(cells ...string) string {
	type nb struct {
		Cells    []notebookCell `json:"cells"`
		Metadata map[string]any `json:"metadata"`
		Format   int            `json:"nbformat"`
		Minor    int            `json:"nbformat_minor"`
	}
	doc := nb{Format: 4, Minor: 5, Metadata: map[string]any{
		"kernelspec":    map[string]string{"display_name": "Python 3 (ipykernel)", "language": "python", "name": "python3"},
		"language_info": map[string]string{"name": "python", "version": "3.11.9"}}}
	run := 0
	for _, text := range cells {
		lines := strings.SplitAfter(text, "\n")
		if strings.HasPrefix(text, "# ") && !strings.Contains(text, "\n") {
			doc.Cells = append(doc.Cells, notebookCell{CellType: "markdown", Metadata: map[string]any{}, Source: lines})
			continue
		}
		run++
		n := run
		doc.Cells = append(doc.Cells, notebookCell{CellType: "code", Count: &n, Metadata: map[string]any{}, Outputs: []any{}, Source: lines})
	}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		panic(fmt.Sprintf("notebook: %v", err))
	}
	return string(b) + "\n"
}

// buildWorkstation: the GPU machine of someone who trains and serves models.
func (s *baitScene) buildWorkstation() {
	s.d = s.d.Sub("workstation")
	d := s.d
	project := canary.Pick(d, "project", []string{"rag-eval", "llm-finetune", "support-bot", "doc-search", "summarizer"})
	base := canary.Pick(d, "base-model", []string{"meta-llama/Llama-3.1-8B-Instruct", "mistralai/Mistral-7B-Instruct-v0.3",
		"Qwen/Qwen2.5-7B-Instruct", "google/gemma-2-9b-it"})
	work := s.home + "/work"
	root := work + "/" + project
	login := baitHostInfo{Alias: canary.Pick(d, "login-alias", []string{"hpc", "cluster", "slurm", "login01"}), User: s.admin.Login, IP: s.addr("ws-login-ip")}
	login.FQDN = login.Alias + "." + s.domain
	store := baitHostInfo{Alias: canary.Pick(d, "store-alias", []string{"datasets", "nas", "storage01"}), User: s.admin.Login, IP: s.addr("ws-store-ip")}
	store.FQDN = store.Alias + "." + s.domain
	tracker := baitHostInfo{FQDN: "mlflow." + s.domain, IP: s.addr("ws-mlflow-ip")}
	s.plan.Hosts = append(s.plan.Hosts, baitHost{Names: []string{tracker.FQDN, tracker.IP}, IP: tracker.IP})
	s.userKey(s.admin.Login+"@"+s.org+"-gpu", "the cluster login node and the dataset store", s.at("ws-key", 0.05, 0.1), login, store)

	// the notebook server the persona runs on 127.0.0.1:8888, with a token of its own
	token := d.Chars("jupyter-token", 48, "0123456789abcdef")
	jupyterAt := s.at("ws-jupyter", 0.1, 0.16)
	s.dir(s.home+"/.jupyter", s.user, 0o755, jupyterAt)
	s.file(baitFile{Path: s.home + "/.jupyter/jupyter_server_config.py", Owner: s.user, Mode: 0o600, At: jupyterAt,
		Text: "# Configuration file for jupyter-server.\n\nc = get_config()  # noqa\n\n" +
			"c.ServerApp.ip = '127.0.0.1'\nc.ServerApp.port = 8888\nc.ServerApp.open_browser = False\n" +
			"c.ServerApp.root_dir = '" + work + "'\nc.ServerApp.token = '" + token + "'\n"})
	s.plant(&canary.Canary{ID: d.ID("jupyter-token"), Kind: canary.KindCredential, Values: []string{token},
		Name: "cowrie bait: Jupyter token", Memo: s.memo("the token of the notebook server on port 8888", s.home+"/.jupyter/jupyter_server_config.py")})

	// the project: its settings, a training script, what it needs, a notebook
	wandb := d.Chars("wandb-key", 40, "0123456789abcdef")
	mlflowPass := d.AlnumSecret("mlflow-pass", 18)
	awsID, awsSecret := d.AWSKeyPair("ws-aws")
	bucket := s.org + "-" + canary.Pick(d, "bucket", []string{"ml-datasets", "training-data", "ml-artifacts"})
	made := s.at("ws-project", 0.3, 0.45)
	for _, dir := range []string{work, root, root + "/notebooks", root + "/configs"} {
		s.dir(dir, s.user, 0o755, made)
	}
	env := fmt.Sprintf("WANDB_API_KEY=%s\nWANDB_ENTITY=%s\nWANDB_PROJECT=%s\n"+
		"MLFLOW_TRACKING_URI=http://%s:5000\nMLFLOW_TRACKING_USERNAME=%s\nMLFLOW_TRACKING_PASSWORD=%s\n"+
		"AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_DEFAULT_REGION=%s\nDATA_BUCKET=s3://%s\n",
		wandb, s.org, project, tracker.FQDN, s.admin.Login, mlflowPass, awsID, awsSecret, canary.Pick(d, "region", baitRegions), bucket)
	s.file(baitFile{Path: root + "/.env", Owner: s.user, Mode: 0o600, At: made + 0.01, Text: env})
	s.file(baitFile{Path: root + "/requirements.txt", Owner: s.user, Mode: 0o644, At: made,
		Text: "torch==2.4.1\ntransformers==4.44.2\ndatasets==2.21.0\npeft==0.12.0\naccelerate==0.34.2\nbitsandbytes==0.43.3\n" +
			"wandb==0.17.9\nmlflow==2.16.0\ns3fs==2024.6.1\npython-dotenv==1.0.1\n"})
	s.file(baitFile{Path: root + "/configs/lora.yaml", Owner: s.user, Mode: 0o644, At: made + 0.02,
		Text: fmt.Sprintf("base_model: %s\ndataset: s3://%s/%s/train.jsonl\neval_dataset: s3://%s/%s/eval.jsonl\noutput_dir: /home/%s/work/%s/out\n"+
			"lora:\n  r: 16\n  alpha: 32\n  dropout: 0.05\n  target_modules: [q_proj, k_proj, v_proj, o_proj]\n"+
			"train:\n  epochs: 3\n  batch_size: 8\n  grad_accum: 4\n  lr: 2.0e-4\n  bf16: true\n", base, bucket, project, bucket, project, s.user, project)})
	s.file(baitFile{Path: root + "/train.py", Owner: s.user, Mode: 0o644, At: made + 0.03, Text: `#!/usr/bin/env python
"""LoRA fine-tune; settings in configs/lora.yaml, keys in .env."""
import os
import sys

import yaml
from datasets import load_dataset
from dotenv import load_dotenv
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments

load_dotenv()
cfg = yaml.safe_load(open(sys.argv[1] if len(sys.argv) > 1 else "configs/lora.yaml"))

tok = AutoTokenizer.from_pretrained(cfg["base_model"], token=os.environ.get("HF_TOKEN"))
tok.pad_token = tok.eos_token
model = AutoModelForCausalLM.from_pretrained(cfg["base_model"], device_map="auto", torch_dtype="auto")
model = get_peft_model(model, LoraConfig(r=cfg["lora"]["r"], lora_alpha=cfg["lora"]["alpha"],
                                         lora_dropout=cfg["lora"]["dropout"],
                                         target_modules=cfg["lora"]["target_modules"], task_type="CAUSAL_LM"))

data = load_dataset("json", data_files={"train": cfg["dataset"], "eval": cfg["eval_dataset"]})
data = data.map(lambda row: tok(row["text"], truncation=True, max_length=2048), remove_columns=["text"])

args = TrainingArguments(cfg["output_dir"], num_train_epochs=cfg["train"]["epochs"],
                         per_device_train_batch_size=cfg["train"]["batch_size"],
                         gradient_accumulation_steps=cfg["train"]["grad_accum"],
                         learning_rate=cfg["train"]["lr"], bf16=cfg["train"]["bf16"],
                         logging_steps=20, eval_strategy="epoch", save_strategy="epoch", report_to=["wandb", "mlflow"])
Trainer(model=model, args=args, train_dataset=data["train"], eval_dataset=data["eval"]).train()
`})
	s.file(baitFile{Path: root + "/notebooks/01-eval.ipynb", Owner: s.user, Mode: 0o644, At: made + 0.08, Text: notebook(
		"# "+project+": compare the tuned adapter with the base model",
		"import os\nimport requests\nfrom dotenv import load_dotenv\n\nload_dotenv(\"../.env\")\nOLLAMA = os.environ.get(\"OLLAMA_HOST\", \"127.0.0.1:11434\")",
		"def ask(model, prompt):\n    r = requests.post(f\"http://{OLLAMA}/api/generate\", json={\"model\": model, \"prompt\": prompt, \"stream\": False}, timeout=120)\n    r.raise_for_status()\n    return r.json()[\"response\"]",
		"import s3fs, json\n\nfs = s3fs.S3FileSystem()\nrows = [json.loads(line) for line in fs.open(\"s3://"+bucket+"/"+project+"/eval.jsonl\")][:200]\nlen(rows)",
		"scores = [(ask(\"llama3.1:8b\", r[\"text\"]), ask(\""+project+":latest\", r[\"text\"])) for r in rows[:20]]")})
	s.file(baitFile{Path: root + "/README.md", Owner: s.user, Mode: 0o644, At: made, Text: "# " + project + "\n\n" +
		"LoRA adapters on `" + base + "`, trained on this box, tracked in W&B and MLflow.\n\n" +
		"    conda activate torch\n    pip install -r requirements.txt\n    python train.py configs/lora.yaml\n\n" +
		"Data lives in `s3://" + bucket + "/" + project + "/`; the keys are in `.env` (not in git).\n" +
		"Long runs go to the cluster: `ssh " + login.Alias + "`, then `sbatch`.\n"})
	// wandb login writes the key here too
	s.file(baitFile{Path: s.home + "/.netrc", Owner: s.user, Mode: 0o600, At: made + 0.05,
		Text: "machine api.wandb.ai\n  login user\n  password " + wandb + "\n"})
	envPath := root + "/.env"
	s.plant(&canary.Canary{ID: d.ID("wandb-key"), Kind: canary.KindCredential, Values: []string{wandb},
		Name: "cowrie bait: experiment tracker API key", Memo: s.memo("the W&B key of "+s.org, envPath, s.home+"/.netrc")})
	s.plant(&canary.Canary{ID: d.ID("mlflow-pass"), Kind: canary.KindCredential, Values: []string{mlflowPass},
		Name: "cowrie bait: MLflow password", Memo: s.memo("the password of "+s.admin.Login+" on "+tracker.FQDN, envPath)})
	s.plant(&canary.Canary{ID: d.ID("ws-aws"), Kind: canary.KindAWS, AccessKeyID: awsID, SecretAccessKey: awsSecret,
		Name: "cowrie bait: AWS access key", Memo: s.memo("the AWS key of the dataset bucket "+bucket, envPath)})

	// root set the machine up and has not been back since the last upgrade
	h := []string{"ubuntu-drivers devices", "apt install -y nvidia-driver-570-server", "reboot", "nvidia-smi",
		"curl -fsSL https://ollama.com/install.sh | sh", "systemctl status ollama", "ollama list",
		"usermod -aG video,render " + s.user, "df -h /", "apt update", "apt list --upgradable", "apt upgrade -y", "uptime", "reboot"}
	s.file(baitFile{Path: "/root/.bash_history", Owner: "root", Mode: 0o600, At: 1,
		Offset: -(60 + d.Intn("reboot", 600)), InPlace: true, Text: strings.Join(h, "\n") + "\n"})
}

// buildPi: a Raspberry Pi someone set up on a home or small-office network.
func (s *baitScene) buildPi() {
	s.d = s.d.Sub("pi")
	d := s.d
	// the Wi-Fi it was set up on before the cable went in: NetworkManager keeps the profile
	ssid := canary.Pick(d, "ssid", []string{title(s.org) + "-Office", title(s.org) + " WiFi", fmt.Sprintf("NETGEAR%02d", d.Intn("ssid-n", 90)+10),
		fmt.Sprintf("TP-Link_%04X", d.Intn("ssid-x", 65536)), title(s.admin.Last) + "Home", fmt.Sprintf("FRITZ!Box 7590 %s", strings.ToUpper(d.Chars("ssid-f", 2, "abcdefghkmnprstuvwxyz")))})
	psk := d.HumanPassword("wifi-psk")
	uuid := d.Chars("wifi-uuid", 32, "0123456789abcdef")
	uuid = uuid[:8] + "-" + uuid[8:12] + "-4" + uuid[13:16] + "-a" + uuid[17:20] + "-" + uuid[20:]
	wifiAt := s.at("pi-wifi", 0.002, 0.01)
	nm := "/etc/NetworkManager/system-connections"
	s.dir("/etc/NetworkManager", "root", 0o755, 0.001)
	s.dir(nm, "root", 0o700, 0.001)
	wifiPath := nm + "/" + ssid + ".nmconnection"
	s.file(baitFile{Path: wifiPath, Owner: "root", Mode: 0o600, At: wifiAt, Text: "[connection]\nid=" + ssid + "\nuuid=" + uuid +
		"\ntype=wifi\ninterface-name=wlan0\n\n[wifi]\nmode=infrastructure\nssid=" + ssid +
		"\n\n[wifi-security]\nauth-alg=open\nkey-mgmt=wpa-psk\npsk=" + psk +
		"\n\n[ipv4]\nmethod=auto\n\n[ipv6]\naddr-gen-mode=default\nmethod=auto\n\n[proxy]\n"})
	s.plant(&canary.Canary{ID: d.ID("wifi-psk"), Kind: canary.KindCredential, Values: []string{psk},
		Name: "cowrie bait: Wi-Fi password", Memo: s.memo("the WPA key of the network "+ssid, wifiPath, s.home+"/.bash_history")})

	// the NAS it copies to, by the name it has on the local network
	nas := baitHostInfo{Alias: "nas", FQDN: canary.Pick(d, "nas-name", []string{"nas.local", "diskstation.local", "storage.local", "backup.local"}),
		User: canary.Pick(d, "nas-user", []string{"backup", "pi", s.admin.First}), IP: s.addr("pi-nas-ip")}
	keyAt := s.at("pi-key", 0.1, 0.2)
	// made on the first day, under the name every new Pi has
	s.userKey(s.user+"@raspberrypi", "the NAS", keyAt, nas)
	s.dir(s.home+"/bin", s.user, 0o755, keyAt+0.02)
	what := canary.Pick(d, "pi-data", []string{"sensors", "camera", "docs", "scans"})
	s.dir(s.home+"/"+what, s.user, 0o755, keyAt)
	script := s.home + "/bin/backup-to-nas.sh"
	s.file(baitFile{Path: script, Owner: s.user, Mode: 0o755, At: keyAt + 0.03, Text: "#!/bin/bash\n# Nightly copy of ~/" + what + " to the NAS.\nset -euo pipefail\n\n" +
		"STAMP=$(date +%F)\ntar czf - -C \"$HOME\" " + what + " | ssh -o BatchMode=yes nas \"cat > /volume1/backup/$(hostname)/" + what + "-$STAMP.tgz\"\n"})

	// dynamic DNS, so the place can be reached from outside
	ddns := canary.Pick(d, "ddns-name", []string{s.org + "-home", s.admin.First + s.admin.Last, s.org + "pi", s.admin.Last + "-" + s.org})
	tok := d.Chars("ddns-token", 32, "0123456789abcdef")
	tok = tok[:8] + "-" + tok[8:12] + "-" + tok[12:16] + "-" + tok[16:20] + "-" + tok[20:]
	ddnsAt := s.at("pi-ddns", 0.25, 0.4)
	s.dir(s.home+"/duckdns", s.user, 0o755, ddnsAt)
	s.file(baitFile{Path: s.home + "/duckdns/duck.sh", Owner: s.user, Mode: 0o700, At: ddnsAt,
		Text: "echo url=\"https://www.duckdns.org/update?domains=" + ddns + "&token=" + tok + "&ip=\" | curl -k -o ~/duckdns/duck.log -K -\n"})
	s.file(baitFile{Path: s.home + "/duckdns/duck.log", Owner: s.user, Mode: 0o644, At: 1, Offset: -(30 + d.Intn("duck-log", 240)), InPlace: true, Text: "OK"})
	s.file(baitFile{Path: "/etc/cron.d/pi-jobs", Owner: "root", Mode: 0o644, At: ddnsAt + 0.01,
		Text: fmt.Sprintf("# dynamic DNS and the nightly copy to the NAS\n*/5 * * * * %s %s/duckdns/duck.sh >/dev/null 2>&1\n%d %d * * * %s %s >/dev/null 2>&1\n",
			s.user, s.home, d.Intn("pi-cron-min", 60), 1+d.Intn("pi-cron-hour", 4), s.user, script)})
	s.plant(&canary.Canary{ID: d.ID("ddns-token"), Kind: canary.KindCredential, Values: []string{tok},
		Name: "cowrie bait: dynamic DNS token", Memo: s.memo("the update token of "+ddns+".duckdns.org", s.home+"/duckdns/duck.sh")})

	// the user's history: the Wi-Fi joined from the command line, the jobs set up, a password typed at the prompt
	h := []string{"sudo raspi-config", "sudo nmcli dev wifi list", "sudo nmcli dev wifi connect \"" + ssid + "\" password \"" + psk + "\"",
		"ip -br a", "sudo apt update", "sudo apt full-upgrade -y", "ssh-keygen -t ed25519", "cat ~/.ssh/id_ed25519.pub",
		"vi ~/.ssh/config", "ssh nas", "mkdir -p bin duckdns " + what, "vi duckdns/duck.sh", "chmod 700 duckdns/duck.sh",
		"./duckdns/duck.sh", "cat duckdns/duck.log", "vi bin/backup-to-nas.sh", "chmod +x bin/backup-to-nas.sh",
		"bin/backup-to-nas.sh", "sudo vi /etc/cron.d/pi-jobs", "sudo -i", s.userPass, "sudo -i", "df -h", "exit"}
	s.file(baitFile{Path: s.home + "/.bash_history", Owner: s.user, Mode: 0o600, At: s.at("user-history", 0.9, 0.96),
		InPlace: true, Text: strings.Join(h, "\n") + "\n"})
	s.plant(&canary.Canary{ID: s.d.ID("user-pass"), Kind: canary.KindCredential, Values: []string{s.userPass},
		Name: "cowrie bait: " + s.user + " password",
		Memo: s.memo("the login password of "+s.user+" typed at the prompt", s.home+"/.bash_history")})
	s.file(baitFile{Path: "/root/.bash_history", Owner: "root", Mode: 0o600, At: 1, Offset: -(60 + d.Intn("reboot", 600)), InPlace: true,
		Text: "apt update\napt full-upgrade -y\nsystemctl status cron\njournalctl -u cron --since today | tail\nreboot\n"})
}
