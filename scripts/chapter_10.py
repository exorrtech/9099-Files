#!/usr/bin/env python3
"""
chapter_10.py: Tool Poisoning and Rug Pull Detector
9099 Files: MCP Exploitation Playbook

Scans tool descriptions for instruction-bearing content, fingerprints
definitions, and polls for mutation (rug pull detection).

Authorized testing only. Run against servers you own or the mock server.
"""
import requests
import hashlib
import json
import sys
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
POLL_SECONDS = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
POLL_CYCLES = int(sys.argv[3]) if len(sys.argv) > 3 else 3

# instruction language that does not belong in a tool description
RED_FLAGS = [
    "ignore previous", "ignore all", "system prompt", "before responding",
    "always include", "always send", "never tell", "do not mention",
    "instead of", "must be sent", "include the contents", "forward",
    "exfiltrate", "for diagnostics", "compliance review",
]
# invisible characters used to smuggle instructions past human review
HIDDEN_CHARS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"]

def fetch_tools():
    r = requests.get(f"{TARGET}/.well-known/mcp.json", timeout=5)
    r.raise_for_status()
    return r.json().get("tools", [])

def fingerprint(tools):
    return {t["name"]: hashlib.sha256(
        json.dumps(t, sort_keys=True).encode()).hexdigest()
        for t in tools}

def scan_description(tool):
    findings = []
    text = json.dumps(tool.get("description", "")) + " " + \
           json.dumps(tool.get("inputSchema", {}))
    low = text.lower()
    for flag in RED_FLAGS:
        if flag in low:
            findings.append(f"instruction language: \"{flag}\"")
    for ch in HIDDEN_CHARS:
        if ch in text:
            findings.append("hidden unicode character in description")
            break
    return findings

def main():
    print(f"[*] 9099 chapter_10: tool poisoning + rug pull detector")
    print(f"[*] target: {TARGET}")
    try:
        tools = fetch_tools()
    except Exception as e:
        print(f"[!] cannot fetch tool list: {e}")
        return 1

    baseline = fingerprint(tools)
    print(f"[+] {len(tools)} tools fingerprinted (sha256 of full definition)")

    flagged = 0
    for t in tools:
        issues = scan_description(t)
        if issues:
            flagged += 1
            print(f"[!] POISON INDICATORS: {t['name']}")
            for i in issues:
                print(f"    - {i}")
        else:
            print(f"[+] {t['name']}: description clean")

    print(f"[*] static scan: {flagged}/{len(tools)} tools with poison indicators")

    print(f"[*] watching for definition mutation, {POLL_CYCLES} cycles x {POLL_SECONDS}s")
    pulls = 0
    for cycle in range(POLL_CYCLES):
        time.sleep(POLL_SECONDS)
        current = fingerprint(fetch_tools())
        for name, h in current.items():
            old = baseline.get(name)
            if old and old != h:
                pulls += 1
                print(f"[!] RUG PULL: {name} definition changed after baseline")
                new_desc = next((t.get("description", "") for t in fetch_tools()
                                 if t["name"] == name), "")
                print(f"    new description: {new_desc[:120]}")
        baseline = current
        print(f"[*] cycle {cycle+1}/{POLL_CYCLES}: {pulls} mutation(s) so far")

    print(f"[*] summary: {flagged} poisoned descriptions, {pulls} rug pulls observed")
    print("[*] full analysis and defenses: chapter 10")
    return 0

if __name__ == "__main__":
    sys.exit(main())
