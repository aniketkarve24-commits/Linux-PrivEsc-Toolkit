import os
import subprocess
import json
import sys
import shutil
import datetime

from vuln_scanner import scan_vulnerabilities
from port_scanner_advanced import analyze_ports
from solutions import get_solution

# ---------- FILES ----------
REPORT_HTML = "Advanced_PrivEsc_Report.html"
REPORT_JSON = "Advanced_PrivEsc_Report.json"

# ---------- STATE ----------
report_content = ""
solutions_block = ""
json_data = []
risk_score = 0

# ---------- MODE ----------
MODE = "deep"
if "--quick" in sys.argv:
    MODE = "quick"

# ---------- SAFE RUN ----------
def run_cmd(cmd):
    try:
        return subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
    except:
        return ""

# ---------- LABEL ----------
def get_label(sev):
    return {
        "high": "🔴 HIGH",
        "medium": "🟠 MEDIUM",
        "low": "🟢 LOW"
    }.get(sev, "⚪ INFO")

# ---------- MITRE ----------
def map_mitre(title):
    mapping = {
        "SUID Binaries": ("T1548.001", 0.9),
        "World Writable Files": ("T1222", 0.7),
        "Cron Jobs": ("T1053.003", 0.85),
        "Sudo Permissions": ("T1548.003", 0.95),
        "Password Exposure": ("T1552.001", 0.8),
        "Linux Capabilities": ("T1548", 0.75),
        "Kernel CVE Matches": ("T1068", 0.9),
        "System Info": ("T1082", 0.3)
    }
    return mapping.get(title, ("T0000", 0.5))

# ---------- GTFOBins ----------
def gtfobins(binary):
    name = os.path.basename(binary.strip())

    return {
        "vim": "vim -> :!sh",
        "find": "find . -exec /bin/sh \\;",
        "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
        "python": "python -c 'import os; os.system(\"/bin/sh\")'",
        "perl": "perl -e 'exec \"/bin/sh\";'",
        "bash": "bash -p",
        "less": "!/bin/sh",
        "more": "!/bin/sh"
    }.get(name, "No GTFOBins entry found")

# ---------- SIM ----------
def simulate_attack(title):
    return {
        "SUID Binaries": "Abuse binary privilege → root shell",
        "Cron Jobs": "Modify cron job → root execution",
        "Sudo Permissions": "Exploit sudo misconfig",
        "World Writable Files": "Inject malicious config"
    }.get(title, "No simulation available")

# ---------- REPORT ----------
def add_to_report(title, severity, desc, fix, output):
    global report_content, json_data, risk_score, solutions_block

    if not output:
        return

    risk_score += {"high": 20, "medium": 10, "low": 5}.get(severity, 1)

    mitre_id, confidence = map_mitre(title)
    attack = simulate_attack(title)
    label = get_label(severity)

    safe_output = str(output).replace("{", "{{").replace("}", "}}")

    report_content += f"""
    <div class="card {severity}">
        <h2>{label} | {title}</h2>
        <p><b>📌 Description:</b> {desc}</p>
        <p><b>🛠 Fix:</b> {fix}</p>
        <p><b>🎯 MITRE:</b> {mitre_id}</p>
        <p><b>📊 Confidence:</b> {confidence}</p>
        <p><b>⚔ Attack:</b> {attack}</p>

        <details>
            <summary>Evidence</summary>
            <pre>{safe_output}</pre>
        </details>
    </div>
    """

    json_data.append({
        "title": title,
        "severity": severity,
        "mitre": mitre_id,
        "confidence": confidence,
        "output": output
    })

    solutions_block += f"""
    <div class="card">
        <h3>{title}</h3>
        <pre>{get_solution(title, desc, output)}</pre>
    </div>
    """

# ---------- HTML SAFE ----------
html_template = """
<html>
<head>
<style>
body {{ font-family: Arial; background:#0f172a; color:#e2e8f0; padding:20px; }}
.card {{ background:#1e293b; padding:15px; margin:10px; border-radius:10px; }}
.high {{ border-left:5px solid red; }}
.medium {{ border-left:5px solid orange; }}
.low {{ border-left:5px solid blue; }}
pre {{ background:black; color:#00ff00; padding:10px; }}
summary {{ color:#38bdf8; cursor:pointer; }}
</style>
</head>
<body>

<h1>⚡ OSCP PrivEsc Framework</h1>
<p>Date: {date}</p>
<h2>Risk Score: {score}%</h2>

{summary}
{content}

<h2>Remediation</h2>
{solutions}

</body>
</html>
"""

# ---------- START ----------
print("[*] Running PrivEsc Toolkit")

user = run_cmd("whoami")
kernel = run_cmd("uname -r")

add_to_report("System Info", "low", "System baseline", "Patch system", f"{user}\n{kernel}")

if MODE == "deep":
    add_to_report("SUID Binaries", "high", "Privilege escalation", "Remove unsafe SUID",
                  run_cmd("find / -perm -4000 2>/dev/null"))

add_to_report("World Writable Files", "high", "Writable risk", "Fix permissions",
              run_cmd("find / -type f -writable 2>/dev/null | head"))

add_to_report("Sudo Permissions", "high", "Privilege risk", "Least privilege",
              run_cmd("sudo -l -n 2>/dev/null"))

add_to_report("Cron Jobs", "medium", "Task risk", "Secure cron",
              run_cmd("ls -la /etc/cron*"))

# ---------- MODULES ----------
vuln, vscore = scan_vulnerabilities()
for v in vuln:
    add_to_report(v[0], "high", "Detected", v[2], v[1])

ports, pfind, pscore = analyze_ports()
for p in pfind:
    add_to_report(p[0], "medium", p[1], p[2], p[0])

# ---------- FINAL ----------
final_score = min(risk_score + vscore + pscore, 100)

summary = f"""
<div class="card">
<h2>🚨 EXECUTIVE SUMMARY</h2>
<p>High: {sum(1 for i in json_data if i['severity']=='high')}</p>
<p>Medium: {sum(1 for i in json_data if i['severity']=='medium')}</p>
<p>Low: {sum(1 for i in json_data if i['severity']=='low')}</p>
</div>
"""

html = html_template.format(
    date=str(datetime.datetime.now()),
    score=final_score,
    content=report_content,
    solutions=solutions_block,
    summary=summary
)

with open(REPORT_HTML, "w") as f:
    f.write(html)

with open(REPORT_JSON, "w") as f:
    json.dump(json_data, f, indent=4)

print("[+] REPORT READY")
print("[+] SCORE:", final_score)
