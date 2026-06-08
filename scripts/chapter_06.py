#!/usr/bin/env python3
"""
MCP Log Leak Scanner
Finds and analyzes MCP server logs for sensitive data exposure
"""
import requests
import re
import json
import sys
from urllib.parse import urljoin

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

LOG_PATTERNS = [
    "logs/", "logs/mcp.log", "log/", "log/mcp.log",
    "debug/logs", ".logs/", "application.log",
    "/logs/access.log", "/var/log/mcp/"
]

SECRET_PATTERNS = [
    (r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', "API Key"),
    (r'aws[_-]?access[_-]?key[_-]?id["\s:=]+["\']?([A-Z0-9]{20})', "AWS Key"),
    (r'aws[_-]?secret[_-]?access[_-]?key["\s:=]+["\']?([A-Za-z0-9/+=]{40})', "AWS Secret"),
    (r'Bearer\s+([a-zA-Z0-9_\-\.]+)', "Bearer Token"),
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI Key"),
    (r'password["\s:=]+["\']?([^\s"\']{8,})', "Password"),
    (r'secret["\s:=]+["\']?([^\s"\']{16,})', "Secret"),
    (r'token["\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})', "Token"),
]

def check_log_endpoint(target, path):
    url = urljoin(target, path)
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def scan_logs(target):
    print(f"[*] MCP Log Leak Scanner")
    print(f"[*] Target: {TARGET}\n")
    
    findings = []
    
    for pattern in LOG_PATTERNS:
        content = check_log_endpoint(TARGET, pattern)
        if content:
            print(f"[!] Found log file: {pattern} ({len(content)} bytes)")
            
            # Search for secrets
            for regex, secret_type in SECRET_PATTERNS:
                matches = re.findall(regex, content, re.IGNORECASE)
                if matches:
                    print(f"    [!] {secret_type}: {len(matches)} found")
                    for m in matches[:5]:
                        print(f"        → {m[:60]}")
                    findings.append((pattern, secret_type, len(matches)))
    
    if not findings:
        print("[-] No obvious log leaks found. Manual review recommended.")
    
    return findings

if __name__ == "__main__":
    scan_logs(TARGET)