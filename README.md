Real-Time IDS Alerting Pipeline: Suricata → Pushover

Building a home lab that pushes live intrusion-detection alerts to my phone, then validating it end-to-end by attacking my own intentionally vulnerable targets — including catching the successful root shell itself on the wire.

Scope note: Every host in this writeup is my own equipment on an isolated, segmented lab network. Targets (Metasploitable 2, DVWA, OWASP Juice Shop) are systems purpose-built to be attacked for training. Nothing here touches any network or machine I don't own.

Table of Contents
Overview
Lab Architecture
Part 1 — The Alerting Pipeline
Part 2 — Tuning Suricata for an 8GB Box
Part 3 — HOME_NET, Directionality, and Getting Auto-Banned
Part 4 — Attack Demo: Recon to Root
Part 5 — What the Alerts Actually Prove
Key Takeaways
Tools Used
Overview

I wanted my firewall to text me. Specifically: when Suricata sees an attack on my lab, I want a push notification on my phone within seconds — signature, source, destination, severity.

This repo documents the full build: the notifier, the rule tuning needed to keep Suricata stable on a memory-constrained firewall, a networking lesson about alert directionality, my own defenses auto-banning my attack box mid-test, and a recon-to-root attack chain that the pipeline detected at every stage — including the root shell itself.

What this demonstrates:

Standing up and tuning an IDS (Suricata on OPNsense)
Writing a custom alert-forwarding pipeline (eve.json → Pushover)
VLAN segmentation and its security implications (in both directions)
A structured attack methodology (recon → service ID → exploit → post-exploitation)
Reading alerts honestly — knowing what a detection does and doesn't prove
Lab Architecture
                          +--------------------------+
                          |        OPNsense          |
   VLAN 10 (attacker)     |  +--------------------+  |    VLAN 60 (targets)
  +---------------+       |  |  Suricata IDS      |  |   +-------------------+
  |  Kali Linux   |------>|  |  (inter-VLAN       |  |-->|  Metasploitable 2 |
  | 192.168.10.57 |       |  |   inspection)      |  |   |  192.168.60.146   |
  +---------------+       |  +---------+----------+  |   +-------------------+
                          |            |             |   |  DVWA / Juice Shop|
                          |   eve.json |             |   +-------------------+
                          |            v             |
                          |  suricata-pushover.py    |
                          +------------+-------------+
                                       |
                                       v
                                +-------------+
                                |  Pushover   |--> iPhone (push alerts)
                                +-------------+
Attacker: Kali Linux on VLAN 10
Targets: Metasploitable 2 (plus DVWA and OWASP Juice Shop) on VLAN 60
Inspection point: Suricata runs on OPNsense, which routes between the VLANs — so all inter-VLAN attack traffic is inspected as it transits the firewall
Delivery: a custom Python script tails Suricata's eve.json and forwards alerts to Pushover

Show Image Zenmap topology: localhost (Kali), OPNsense as the gateway, and the target host 192.168.60.146.

Part 1 — The Alerting Pipeline

Suricata writes every event to /var/log/suricata/eve.json as newline-delimited JSON. The notifier tails that file, filters for alert events, de-duplicates, and forwards to Pushover's API.

Design decisions:

Choice	Reason
Poll eve.json on a 1-minute cron	Simple, no long-running daemon to babysit on the firewall
Track file offset + inode in a state file	Only send new alerts; survive log rotation
De-duplicate on signature + source IP	One noisy scan can generate thousands of identical hits — collapse them
Severity gate	Optionally drop low-priority INFO noise

Core logic (abridged):

python
# Tail new lines since last run, using a saved byte offset + inode
# (inode check handles log rotation - reset offset if the file changed)
for line in new_lines:
    e = json.loads(line)
    if e.get("event_type") != "alert":
        continue
    a = e["alert"]
    sev = a.get("severity", 3)
    if sev > MAX_SEV:                 # optional severity gate
        continue
    key = a["signature"] + "|" + e["src_ip"]
    if key in recently_seen:          # de-dupe window
        continue
    push_to_pushover(
        title=f"Suricata: {a['category']}",
        message=f"{a['signature']}\n{e['src_ip']} -> {e['dest_ip']}:{e.get('dest_port','')} (sev {sev})"
    )

The result: alerts land on my phone as TIME SENSITIVE push notifications with the signature name, direction, and severity.

On the OPNsense shell: OPNsense's console uses a restricted tcsh that mangles multi-line paste and heredocs. To deploy/edit the script reliably I base64-encoded it and decoded straight to disk, sidestepping the shell's paste quirks:

sh
echo '<base64-blob>' | openssl base64 -d -A > /usr/local/bin/suricata-pushover.py
Part 2 — Tuning Suricata for an 8GB Box

My OPNsense box only has 8GB of RAM, and Suricata was spiking memory hard enough to crash it — usually during a rule reload, when it briefly holds both the old and new rulesets in memory at once. Fewer rules = smaller spike.

The key insight: my lab is isolated, so IP/domain reputation feeds never fire. Feeds like Feodo Tracker, ThreatFox, URLhaus, and the botnet C2 lists only match traffic to known-malicious internet infrastructure. My lab IPs aren't on any blocklist, so those rules produce zero alerts while still consuming memory on every reload.

Rulesets removed (reputation/blocklist feeds — no value in an isolated lab):

abuse.ch/Feodo Tracker, abuse.ch/ThreatFox, abuse.ch/URLhaus
ET open/botcc, botcc.portgrouped, compromised, threatview_CS_c2
ET open/emerging-mobile_malware, emerging-exploit_kit

Rulesets kept (signature-based — these actually fire when Kali attacks the targets):

emerging-scan — nmap and sweeps
emerging-exploit, emerging-shellcode, emerging-attack_response
emerging-ftp, emerging-telnet, emerging-netbios
emerging-web_server, emerging-remote_access

Other memory levers:

Interface count matters. Each interface Suricata inspects multiplies memory use. For an inter-VLAN lab I only need it on the one segment the attack traffic crosses — not WAN + every VLAN. This alone was a major stabilizer.
Trimming ~22 rulesets down to ~9 removed the crash-on-reload behavior.
Part 3 — HOME_NET, Directionality, and Getting Auto-Banned

Two lessons landed here — one about how Suricata rules match, and one about my own defenses biting back.

Rule directionality

Most ET attack rules are directional — they match $EXTERNAL_NET -> $HOME_NET, and EXTERNAL_NET is defined as everything not in HOME_NET.

In my setup the attacker (Kali) sits on a subnet excluded from HOME_NET, while the targets are inside it. So:

Kali -> target reads as EXTERNAL_NET -> HOME_NET → matches the attack rules → alerts fire.

If I'd put the attacker inside HOME_NET, its traffic would read as HOME_NET -> HOME_NET, and most of those directional rules would not match. "Attacker outside HOME_NET, victim inside" is the correct lab layout for generating meaningful IDS alerts — and it clarified why inter-VLAN traffic gets inspected at all: the firewall routes between the VLANs, so Suricata sees it in transit.

My own defenses banned my attack box

I also run CrowdSec on the firewall. Partway through testing, it auto-banned my Kali box:

Show Image

ID       Source     Scope:Value          Reason                                Action
3804835  crowdsec   Ip:192.168.10.57     firewallservices/pf-scan-multi_ports  ban

CrowdSec flagged my port scanning (pf-scan-multi_ports, 16 events) as exactly what it is — hostile behavior — and banned the source. Fix was to allowlist the lab subnet so I could keep testing:

sh
cscli allowlists create lab -d "pentest lab"
cscli allowlists add lab 192.168.10.57
# 1 decisions deleted by allowlists

Worth noting: the same decisions list shows CrowdSec banning real internet attackers at the same time — http-probing and http-backdoors-attempts from hosts in multiple countries. So this isn't just lab theater; the behavioral layer is doing real work on the WAN side while Suricata handles signature detection on the lab side.

Takeaway: whitelisting your own tooling is a real operational step. And getting auto-banned by your own stack is a good sign — it means the defense works.

Part 4 — Attack Demo: Recon to Root

A structured chain against Metasploitable 2, chosen so each stage trips a different detection category — and every stage showed up on my phone.

Stage 1 — Recon
bash
nmap -sV 192.168.60.146
sudo nmap -O -F 192.168.60.0/24     # subnet sweep for the topology map

This lit up a stack of ET SCAN alerts — Nmap Scripting Engine user-agent, potential SSH scan, OS-detection probe, and "suspicious inbound" hits on the MySQL/MSSQL/Oracle/PostgreSQL/VNC/RDP ports as nmap walked the services. Recon is the loudest, most reliably detected stage of any attack.

Stage 2 — Web attack surface
bash
nikto -h http://192.168.60.146

Nikto throws a large volume of known-malicious web requests, tripping ET WEB_SERVER / ET EXPLOIT / GPL WEB_SERVER signatures — XSS attempts, .htaccess access, /system32/ and cmd.exe in URI, /msadc/samples/ access, and more.

(See Part 5 for the important caveat on the CVE-named web alerts.)

Stage 3 — Exploitation → Root

The clean, fully-consistent exploit on this box is the Samba username-map-script command injection, CVE-2007-2447.

My first attempt used a reverse payload (cmd/unix/reverse_netcat). The exploit fired but no session opened:

Show Image

The cause was my own segmentation: a reverse shell needs the victim (VLAN 60) to connect back to the attacker (VLAN 10). My firewall permits VLAN 10 → VLAN 60 (the forward attack path) but not the return path, so the callback was silently dropped.

Switching to a bind payload (cmd/unix/bind_netcat) — where the victim opens a listener and the attacker connects in, the same direction as the working attack traffic — landed the shell immediately:

bash
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.60.146
set LHOST 192.168.10.57
set PAYLOAD cmd/unix/bind_netcat
run
bash
whoami
# root

Show Image

🎥 Watch the terminal recording of the exploit landing root

Takeaway: segmentation cuts both ways. The same firewall rules that contain an attacker can also break a naive payload choice — and knowing why is the difference between "it didn't work" and "here's exactly which rule dropped it and the payload type that works around it."

The detection that ties it together

When the root shell ran id, Suricata caught the response coming back from the victim:

Suricata: Potentially Bad Traffic
GPL ATTACK_RESPONSE id check returned root
192.168.60.146 -> 192.168.10.57 (sev 2)

Note the direction: 192.168.60.146 -> 192.168.10.57 — target back to attacker, the reverse of every scan alert. That's the IDS detecting the compromised host shipping uid=0(root) output down the shell. The successful exploitation itself generated a detection. Recon, web attacks, and the root shell — all caught.

Part 5 — What the Alerts Actually Prove

This matters, so I'm calling it out explicitly rather than letting the screenshots imply more than they should.

The single best screenshot from this project shows two different Samba CVEs in one frame — and only one was my actual attack path.

Show Image

The SMB traffic tripped ET EXPLOIT Samba Arbitrary Module Loading (CVE-2017-7494) — "SambaCry." That's the signature that matched on port 445, and it's the flashy, recognizable CVE in the alert.
But the shell I actually landed was via CVE-2007-2447 (username map script command injection) — a different, older Samba bug.

So the impressive-looking CVE-2017-7494 alert is a detection of Samba exploit activity; the exploitation that gave me root was CVE-2007-2447. Same service, two different CVEs, and only reading the details tells them apart. (This same screenshot also shows CrowdSec banning real internet attackers hitting my public-facing services — lab detections and live-threat blocks in one feed.)

The same logic applies to the web stage: nikto tripped CVE-named alerts (e.g. a VMware Spring directory-traversal signature) against a box that doesn't even run that software. Those are pattern matches on the requests, not real exploits.

Event	What it proves
ET SCAN stack (nmap, SSH/VNC/SQL probes)	IDS detects reconnaissance — real and accurate
CVE-named web alerts from nikto	IDS detects exploit attempts by signature (detection yes; exploitation no — target isn't that software)
ET EXPLOIT Samba ... (CVE-2017-7494)	IDS detects Samba exploit activity on port 445 (detection) — not the CVE I actually exploited
ATTACK_RESPONSE id check returned root	A real compromise — the victim returned root to the attacker after the exploit landed
Samba CVE-2007-2447 + root shell	Genuine vulnerability on this box, exploited to root (detection + exploitation)

So this project has two honest halves:

Detection story — the pipeline catching recon and web-exploit attempts in real time.
Exploitation story — CVE-2007-2447 → root, which is genuinely present and exploitable on Metasploitable, and which the IDS also caught via the id check returned root response.

Keeping those straight is part of the point. An IDS alert tells you someone tried something; the direction and signature tell you whether they succeeded. Reading them correctly is the actual skill.

Key Takeaways
Detection ≠ exploitation. An alert proves an attempt was seen, not that it worked — except when it does: the id check returned root response is the IDS catching a real compromise. Reading direction and signature is what tells them apart.
Reputation feeds are dead weight in an isolated lab — trimming them fixed my memory-driven crashes. Match the ruleset to the actual threat surface.
Rule reloads are the memory spike. Fewer rules = smaller spike = stable IDS on modest hardware.
Suricata rules are directional. HOME_NET / EXTERNAL_NET placement determines whether attack rules fire at all.
Segmentation cuts both ways. It contains attackers and breaks naive reverse shells — understanding the return path is what lets you adapt (bind vs. reverse).
Your own defenses will bite you — CrowdSec auto-banned my attack box for port scanning. Whitelisting your tooling is a real step, and the ban proves the control works.
Build the feedback loop. Real-time alerts on my phone turned "logs I never read" into "I know the instant something happens."
Tools Used
OPNsense — firewall / router, IDS host, VLAN segmentation
Suricata — IDS engine (ET Open ruleset)
CrowdSec — behavioral detection + auto-banning (separate pipeline)
Pushover — push-notification delivery
Python — custom eve.json → Pushover forwarder
Kali Linux — attack platform
Metasploit Framework, nmap, nikto — recon and exploitation
Metasploitable 2, DVWA, OWASP Juice Shop — intentionally vulnerable targets

Built and documented as part of my cybersecurity coursework and home-lab practice. All activity was performed on isolated systems I own.
