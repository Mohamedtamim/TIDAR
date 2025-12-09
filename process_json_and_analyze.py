#!/usr/bin/env python3
import json
import os
import subprocess

# --- إعداد المسارات ---
GHIDRA_BINARY = "/usr/share/ghidra/support/analyzeHeadless"
GHIDRA_PROJECT_PATH = "/home/godfather/Desktop/GhidraProject"
GHIDRA_PROJECT_NAME = "AutoProject"
GHIDRA_SCRIPTS = "/home/godfather/Desktop/GhidraScripts"

JSON_FILE = "/home/godfather/Desktop/log+exe/Suspicious_Logs.json"
REPORTS_DIR = "/home/godfather/Desktop/GhidraReports"

# --- تأكد من وجود مجلد التقارير ---
os.makedirs(REPORTS_DIR, exist_ok=True)

# --- دالة إرسال الملف لـ Ghidra وتحليلها ---
def analyze_with_ghidra(file_path):
    print("[+] Sending to Ghidra:", file_path)

    cmd = [
        GHIDRA_BINARY,
        GHIDRA_PROJECT_PATH,
        GHIDRA_PROJECT_NAME,
        "-import", file_path,
        "-postScript", "generate_html_report.py",
        "-scriptPath", GHIDRA_SCRIPTS,
        "-overwrite"
    ]

    try:
        subprocess.run(cmd, check=True)
        print("[+] Analysis finished. Report saved in", REPORTS_DIR)
    except subprocess.CalledProcessError as e:
        print("[-] Ghidra analysis failed:", e)

# --- دالة قراءة وتحليل الـ JSON log ---
def process_json(json_file):
    print("[+] Reading JSON log:", json_file)
    with open(json_file, "r") as f:
        logs = json.load(f)

    for entry in logs:  # logs هنا list
        file_path = entry.get("file_path")
        if file_path and os.path.exists(file_path):
            analyze_with_ghidra(file_path)
        else:
            print("[-] File not found:", file_path)

# --- Main ---
if __name__ == "__main__":
    process_json(JSON_FILE)
