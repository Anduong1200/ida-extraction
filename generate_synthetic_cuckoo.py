#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Synthetic Cuckoo Report Generator
=================================
Generates fake Cuckoo Sandbox JSON reports for testing the HoloGuard pipeline.
Simulates a ransomware-like behavior pattern.

Usage:
    python generate_synthetic_cuckoo.py --output synthetic_report.json

Author: Antigravity Agent
License: MIT
"""

import json
import random
import argparse
from pathlib import Path

def generate_report(output_path: Path):
    """Generate a synthetic report."""
    
    # Template
    report = {
        "info": {"id": 1, "score": 8.5},
        "target": {"category": "file", "file": {"name": "malware.exe", "sha256": "abcdef123456"}},
        "network": {
            "hosts": ["192.168.1.100", "8.8.8.8", "cnc-server.com"],
            "dns": [{"request": "cnc-server.com", "answers": [{"data": "1.2.3.4"}]}],
            "tcp": [{"src": "192.168.56.101", "dst": "1.2.3.4", "dport": 80}]
        },
        "behavior": {
            "processes": []
        }
    }
    
    # 1. Main Process (Malware)
    pid_main = 1000
    p_main = {
        "process_id": pid_main,
        "parent_id": 400, # explorer.exe
        "process_name": "malware.exe",
        "command_line": "\"C:\\Users\\Admin\\malware.exe\"",
        "calls": []
    }
    
    # Behavior: Detect VM -> Connect C2 -> Drop Ransom Note -> Encrypt
    
    # API Sequence
    calls = []
    t = 0.0
    
    # Check Environment
    calls.append({"api": "GetSystemInfo", "category": "system", "arguments": {}, "time": t, "return": "0"})
    t += 0.01
    calls.append({"api": "GetComputerNameW", "category": "system", "arguments": {"lpBuffer": "WIN-SANDBOX"}, "time": t, "return": "1"})
    t += 0.02
    
    # Connect C2
    calls.append({"api": "InternetOpenA", "category": "network", "arguments": {"sAgent": "Mozilla/5.0"}, "time": t, "return": "0x1234"})
    t += 0.05
    calls.append({"api": "InternetConnectA", "category": "network", "arguments": {"lpszServerName": "cnc-server.com", "nServerPort": 80}, "time": t, "return": "0x1235"})
    t += 0.1
    
    # File Operations
    target_files = ["C:\\Users\\Admin\\Documents\\report.docx", "C:\\Users\\Admin\\Pictures\\photo.jpg"]
    
    for f in target_files:
        calls.append({"api": "CreateFileW", "category": "file", "arguments": {"filepath": f, "dwDesiredAccess": "GENERIC_READ"}, "time": t, "return": "0x100"})
        t += 0.01
        calls.append({"api": "ReadFile", "category": "file", "arguments": {"hFile": "0x100"}, "time": t, "return": "1"})
        t += 0.01
        calls.append({"api": "WriteFile", "category": "file", "arguments": {"hFile": "0x100", "Buffer": "ENCRYPTED_DATA..."}, "time": t, "return": "1"})
        t += 0.01
        calls.append({"api": "CloseHandle", "category": "handle", "arguments": {"hObject": "0x100"}, "time": t, "return": "1"})
        t += 0.02
        
    # Registry Persistence
    calls.append({"api": "RegOpenKeyExW", "category": "registry", "arguments": {"hKey": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, "time": t, "return": "0"})
    t += 0.01
    calls.append({"api": "RegSetValueExW", "category": "registry", "arguments": {"lpValueName": "MalwareUpdater", "lpData": "C:\\Users\\Admin\\malware.exe"}, "time": t, "return": "0"})

    p_main["calls"] = calls
    report["behavior"]["processes"].append(p_main)
    
    # 2. Child Process (cmd.exe delete volume shadows)
    pid_child = 1001
    calls.append({"api": "CreateProcessW", "category": "process", "arguments": {"lpApplicationName": "cmd.exe", "lpCommandLine": "/c vssadmin delete shadows /all"}, "time": t, "return": "1"})
    
    p_child = {
        "process_id": pid_child,
        "parent_id": pid_main,
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c vssadmin delete shadows /all",
        "calls": [
            {"api": "NtTerminateProcess", "category": "process", "arguments": {}, "time": t+1.0, "return": "0"}
        ]
    }
    report["behavior"]["processes"].append(p_child)

    # Save
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
        
    print(f"Generated synthetic report at: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('synthetic_cuckoo.json'))
    args = parser.parse_args()
    generate_report(args.output)
