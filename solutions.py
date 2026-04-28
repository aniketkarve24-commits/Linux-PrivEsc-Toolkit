# solutions.py (OSCP / PRO LEVEL UPGRADE)

def get_solution(title, desc="", output=""):
    t = title.lower()

    def block(auto, manual, exploit, impact, note):
        return f"""
==============================
🛠 AUTO FIX
==============================
{auto}

==============================
🔍 MANUAL ANALYSIS
==============================
{manual}

==============================
⚔ EXPLOIT PATH (HOW ATTACK HAPPENS)
==============================
{exploit}

==============================
💥 IMPACT
==============================
{impact}

==============================
⚠ IMPORTANT NOTE
==============================
{note}
"""

    # ================= SUID =================
    if "suid" in t:
        return block(
            auto="chmod u-s <binary> (only non-critical binaries)",
            manual=(
                "find / -perm -4000 -type f\n"
                "Check GTFOBins for each binary\n"
                "Identify misconfigured privileged binaries"
            ),
            exploit=(
                "If binary is GTFOBins-exploitable:\n"
                "Example:\n"
                "find . -exec /bin/sh -p \\; -quit\n"
                "OR abuse binary to spawn root shell"
            ),
            impact="Attacker can escalate from low user → root shell",
            note="Never remove SUID blindly (critical system break risk)"
        )

    # ================= SUDO =================
    if "sudo" in t:
        return block(
            auto="Remove NOPASSWD entries in /etc/sudoers",
            manual=(
                "sudo -l\n"
                "Identify allowed binaries\n"
                "Check GTFOBins sudo abuse list"
            ),
            exploit=(
                "If allowed:\n"
                "sudo vim → :!sh\n"
                "sudo python → os.system('/bin/sh')\n"
                "sudo find → -exec /bin/sh \\;"
            ),
            impact="Full privilege escalation via misconfigured sudo rules",
            note="Least privilege principle must always be enforced"
        )

    # ================= CRON =================
    if "cron" in t:
        return block(
            auto="chmod 644 /etc/cron*",
            manual=(
                "cat /etc/crontab\n"
                "Check writable scripts in cron jobs\n"
                "Inspect cron.d, cron.daily, cron.hourly"
            ),
            exploit=(
                "If script is writable:\n"
                "inject reverse shell payload\n"
                "wait for root cron execution"
            ),
            impact="Automatic root execution (time-based privilege escalation)",
            note="Cron misconfig = silent persistent root access"
        )

    # ================= WRITABLE FILE =================
    if "writable" in t:
        return block(
            auto="chmod 644 <file>",
            manual=(
                "find / -writable -type f\n"
                "Check service dependency on file\n"
                "Identify config injection points"
            ),
            exploit=(
                "Overwrite config / script\n"
                "Inject malicious command or reverse shell\n"
                "Trigger service restart"
            ),
            impact="Configuration hijacking → privilege escalation",
            note="Writable system files are high-risk attack vectors"
        )

    # ================= CAPABILITIES =================
    if "capabilities" in t:
        return block(
            auto="setcap -r <binary>",
            manual=(
                "getcap -r /\n"
                "Identify binaries with cap_net_admin, cap_sys_admin"
            ),
            exploit=(
                "Example:\n"
                "nmap --interactive → !sh\n"
                "python cap_sys_ptrace → inject process"
            ),
            impact="Privilege escalation without SUID",
            note="Capabilities often bypass traditional SUID detection"
        )

    # ================= PATH =================
    if "path" in t:
        return block(
            auto="Remove writable directories from PATH",
            manual=(
                "echo $PATH\n"
                "Check '.' or user writable directories\n"
                "Inspect script execution order"
            ),
            exploit=(
                "Place malicious binary in PATH\n"
                "Example: fake 'ls' or 'cat'\n"
                "Trigger privileged script execution"
            ),
            impact="Command hijacking → privilege escalation",
            note="PATH injection is common in misconfigured scripts"
        )

    # ================= PASSWORD =================
    if "password" in t or "credential" in t:
        return block(
            auto="Clear history + rotate credentials",
            manual=(
                "grep -Ri password /\n"
                "Check bash history, config files"
            ),
            exploit=(
                "Use leaked creds for SSH/SUDO access\n"
                "Reuse password across services"
            ),
            impact="Full account takeover",
            note="Credential leaks often lead to complete system compromise"
        )

    # ================= HTTP =================
    if "http" in t or "80" in t:
        return block(
            auto="Disable unused web server",
            manual=(
                "Check running services\n"
                "Review Apache/Nginx config"
            ),
            exploit=(
                "Web shell upload\n"
                "LFI → RCE\n"
                "Misconfigured admin panel abuse"
            ),
            impact="Remote code execution → system takeover",
            note="Web services are primary attack entry points"
        )

    # ================= DEFAULT =================
    return block(
        auto="No auto fix available",
        manual="Perform manual security audit",
        exploit="Analyze manually based on context",
        impact="Depends on system configuration",
        note="Requires human analysis for accurate assessment"
    )
