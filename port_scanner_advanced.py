import subprocess

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

# ---------- PORT SCAN (IMPROVED) ----------
def scan_ports():
    output = run_cmd("ss -tulnp")

    ports = []
    for line in output.splitlines():
        if "LISTEN" not in line:
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        addr = parts[4]

        # IPv4 / IPv6 handling
        if ":" in addr:
            port = addr.rsplit(":", 1)[-1]

            if port.isdigit():
                ports.append(port)

    return sorted(list(set(ports)))

# ---------- SERVICE DETECTION ----------
def detect_service(port):
    services = {
        "22": ("SSH Service", "Brute-force possible if password auth enabled"),
        "80": ("HTTP Service", "Web server exposed"),
        "443": ("HTTPS Service", "Secure web traffic (check TLS config)"),
        "21": ("FTP Service", "Cleartext credentials risk"),
        "3306": ("MySQL Service", "Database exposure risk"),
        "3389": ("RDP Service", "Remote desktop attack surface"),
        "8080": ("Alternative HTTP", "Web app possibly running"),
    }

    return services.get(
        port,
        ("Unknown Service", "Manual investigation required")
    )

# ---------- RISK ENGINE ----------
def analyze_ports():
    ports = scan_ports()
    findings = []
    score = 0

    if not ports:
        return ports, findings, 0

    for p in ports:
        service, desc = detect_service(p)

        severity = "LOW"
        risk = 5

        # ---------------- SECURITY LOGIC ----------------
        if p == "22":
            severity = "MEDIUM"
            risk = 15

        elif p in ["21", "3306", "3389"]:
            severity = "HIGH"
            risk = 25

        elif p in ["80", "8080"]:
            severity = "MEDIUM"
            risk = 20

        elif p == "443":
            severity = "LOW"
            risk = 10

        else:
            severity = "LOW"
            risk = 5

        findings.append((
            f"{service} ({p})",
            desc,
            "Restrict access, close unused service, harden configuration",
            severity
        ))

        score += risk

    score = min(score, 100)

    return ports, findings, score
