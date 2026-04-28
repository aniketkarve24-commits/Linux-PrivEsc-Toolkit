import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import subprocess
import os
import datetime
import queue

# ---------- GLOBAL ----------
is_scanning = False
risk_value = 0
log_queue = queue.Queue()

# ---------- TIME ----------
def now():
    return datetime.datetime.now().strftime("%H:%M:%S")

# ---------- LOG ----------
def log(tag, msg):
    output_box.insert(tk.END, f"[{now()}] [{tag}] {msg}\n")
    output_box.see(tk.END)

# ---------- LIVE QUEUE PROCESSOR ----------
def process_queue():
    global risk_value

    while not log_queue.empty():
        tag, line = log_queue.get()

        line_upper = line.upper()

        if "HIGH" in line_upper:
            risk_value += 10
            tag = "HIGH"
        elif "MEDIUM" in line_upper:
            risk_value += 5
            tag = "WARN"
        else:
            tag = "INFO"

        risk_value = min(risk_value, 100)

        log(tag, line)
        risk_label.config(text=f"Risk Score: {risk_value}%")

    root.after(100, process_queue)

# ---------- SCAN ----------
def run_scan(mode):
    global is_scanning, risk_value
    is_scanning = True
    risk_value = 0

    clear_output()

    log("SCAN", f"Starting {mode.upper()} scan...")
    status_label.config(text=f"STATUS: RUNNING ({mode})", fg="#f59e0b")

    progress.start(10)

    cmd = ["python3", "tool.py", f"--{mode}"]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(process.stdout.readline, ''):
            if line:
                log_queue.put(("INFO", line.strip()))

        process.stdout.close()
        process.wait()

    except Exception as e:
        log_queue.put(("HIGH", f"ERROR: {str(e)}"))

    progress.stop()
    is_scanning = False

    status_label.config(text="STATUS: COMPLETED", fg="#22c55e")
    log("SCAN", "✔ Scan Completed Successfully")

# ---------- THREAD ----------
def start_scan(mode):
    if is_scanning:
        log("WARN", "Scan already running...")
        return

    thread = threading.Thread(target=run_scan, args=(mode,))
    thread.daemon = True
    thread.start()

# ---------- REPORT ----------
def open_report():
    if os.path.exists("Advanced_PrivEsc_Report.html"):
        log("INFO", "Opening Report...")
        os.system("xdg-open Advanced_PrivEsc_Report.html")
    else:
        log("HIGH", "Report not found!")

# ---------- CLEAR ----------
def clear_output():
    output_box.delete(1.0, tk.END)

# ---------- EXIT ----------
def exit_app():
    root.destroy()

# ---------- GUI ----------
root = tk.Tk()
root.title("⚡ PrivEsc Live Dashboard (PRO)")
root.geometry("900x620")
root.configure(bg="#0f172a")

# ---------- TITLE ----------
title = tk.Label(
    root,
    text="🔥 LIVE PRIVILEGE ESCALATION DASHBOARD",
    font=("Consolas", 16, "bold"),
    fg="#38bdf8",
    bg="#0f172a"
)
title.pack(pady=10)

# ---------- STATUS ----------
status_frame = tk.Frame(root, bg="#1e293b")
status_frame.pack(fill="x", padx=15)

status_label = tk.Label(
    status_frame,
    text="STATUS: IDLE",
    bg="#1e293b",
    fg="white",
    font=("Consolas", 10, "bold")
)
status_label.pack(side="left", padx=10)

risk_label = tk.Label(
    status_frame,
    text="Risk Score: 0%",
    bg="#1e293b",
    fg="#facc15",
    font=("Consolas", 10, "bold")
)
risk_label.pack(side="right", padx=10)

# ---------- BUTTONS ----------
btn_frame = tk.Frame(root, bg="#0f172a")
btn_frame.pack(pady=10)

btn_style = {
    "font": ("Consolas", 10, "bold"),
    "width": 16,
    "bg": "#1e293b",
    "fg": "white",
    "activebackground": "#334155"
}

tk.Button(btn_frame, text="⚡ Quick Scan", command=lambda: start_scan("quick"), **btn_style).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="🔥 Deep Scan", command=lambda: start_scan("deep"), **btn_style).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="📊 Open Report", command=open_report, **btn_style).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="🧹 Clear", command=clear_output, **btn_style).grid(row=0, column=3, padx=5)
tk.Button(btn_frame, text="❌ Exit", command=exit_app, **btn_style).grid(row=0, column=4, padx=5)

# ---------- PROGRESS ----------
progress = ttk.Progressbar(root, mode="indeterminate")
progress.pack(fill="x", padx=20, pady=10)

# ---------- OUTPUT ----------
output_box = scrolledtext.ScrolledText(
    root,
    width=100,
    height=28,
    bg="#020617",
    fg="#22c55e",
    insertbackground="white",
    font=("Consolas", 9)
)
output_box.pack(padx=10, pady=10)

# ---------- START LOOP ----------
root.after(100, process_queue)

root.mainloop()
