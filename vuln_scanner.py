import subprocess
import os

# ---------- SAFE EXEC ----------
def run_cmd(cmd):
    try:
        return subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
    except:
        return ""

# ---------- MITRE ----------
MITRE = {
    "SUID Binaries Found": "T1548.001",
    "Writable Root Files": "T1068",
    "Sudo Misconfiguration": "T1548.003",
    "Writable Cron Jobs": "T1053.003",
    "Linux Capabilities": "T1068",
    "Insecure PATH Variable": "T1574.007",
    "Possible Credential Exposure": "T1552"
}

# ---------- CLEAN ----------
def clean_output(data, limit=1000):
    if not data:
        return ""
    return "\n".join(data.splitlines()[:50])[:limit]

# ---------- HELPERS ----------
def has_write_permission(path):
    try:
        return os.access(path, os.W_OK)
    except:
        return False

# ---------- SCANNER ----------
def scan_vulnerabilities():
    findings = []
    score = 0

    # =========================
    # 1. SUID BINARIES
    # =========================
    suid = run_cmd("find / -perm -4000 -type f 2>/dev/null")

    if suid.strip():
        findings.append((
            "SUID Binaries Found",
            clean_output(suid),
            "Audit SUID binaries and remove unnecessary privilege escalation paths",
            "HIGH",
            MITRE["SUID Binaries Found"]
        ))
        score += 20

    # =========================
    # 2. WRITABLE ROOT FILES (FIXED LOGIC)
    # =========================
    writable_root = run_cmd("find / -type f -user root -writable 2>/dev/null")

    if writable_root.strip():
        findings.append((
            "Writable Root Files",
            clean_output(writable_root),
            "Critical misconfiguration: root-owned writable files",
            "CRITICAL",
            MITRE["Writable Root Files"]
        ))
        score += 30

    # =========================
    # 3. SUDO MISCONFIG
    # =========================
    sudo = run_cmd("sudo -l -n 2>/dev/null")

    if "NOPASSWD" in sudo or "(ALL" in sudo:
        findings.append((
            "Sudo Misconfiguration",
            clean_output(sudo),
            "Check sudoers file and enforce least privilege",
            "CRITICAL",
            MITRE["Sudo Misconfiguration"]
        ))
        score += 25

    # =========================
    # 4. CRON JOBS (REAL CHECK FIXED)
    # =========================
    cron_files = run_cmd("find /etc/cron* -type f 2>/dev/null")

    writable_cron = []
    for f in cron_files.splitlines():
        if f and os.path.exists(f) and os.access(f, os.W_OK):
            writable_cron.append(f)

    if writable_cron:
        findings.append((
            "Writable Cron Jobs",
            clean_output("\n".join(writable_cron)),
            "Cron jobs must not be writable by non-root users",
            "HIGH",
            MITRE["Writable Cron Jobs"]
        ))
        score += 25

    # =========================
    # 5. LINUX CAPABILITIES (FILTERED)
    # =========================
    caps = run_cmd("getcap -r / 2>/dev/null")

    dangerous_caps = []
    for line in caps.splitlines():
        if any(x in line for x in ["cap_setuid", "cap_sys_admin", "cap_net_raw", "cap_dac_override"]):
            dangerous_caps.append(line)

    if dangerous_caps:
        findings.append((
            "Linux Capabilities Misuse",
            clean_output("\n".join(dangerous_caps)),
            "Review dangerous capabilities assigned to binaries",
            "HIGH",
            MITRE["Linux Capabilities"]
        ))
        score += 20

    # =========================
    # 6. PATH HIJACK (FIXED ACCURACY)
    # =========================
    path = run_cmd("echo $PATH")

    if path.startswith(".") or ":.:" in path:
        findings.append((
            "Insecure PATH Variable",
            path,
            "Remove '.' from PATH to prevent binary hijacking",
            "MEDIUM",
            MITRE["Insecure PATH Variable"]
        ))
        score += 10

    # =========================
    # 7. CREDENTIAL LEAK (CLEANED)
    # =========================
    creds = run_cmd(
        "grep -iE 'password|passwd|token|secret|key' ~/.bash_history 2>/dev/null"
    )

    if creds.strip():
        findings.append((
            "Possible Credential Exposure",
            clean_output(creds),
            "Avoid storing secrets in shell history or scripts",
            "MEDIUM",
            MITRE["Possible Credential Exposure"]
        ))
        score += 10

    # =========================
    # FINAL SCORE
    # =========================
    score = min(score, 100)

    return findings, score
