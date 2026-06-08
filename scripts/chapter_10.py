#!/usr/bin/env python3
"""
MCP Dependency Attack — Typosquatting Detector
Checks if MCP server uses packages with typosquatted lookalikes on PyPI/npm
"""
import requests
import json
import sys

TARGET_PYPI = "https://pypi.org/pypi"
TARGET_NPM = "https://registry.npmjs.org"

COMMON_PACKAGES = [
    "requests", "urllib3", "yaml", "json", "numpy", "pandas",
    "discord", "slack", "twilio", "boto3", "botocore", "aiohttp",
    "certifi", "chardet", "idna", "charset-normalizer"
]

TYPOSQUATTED = {
    "requests": ["requessts", "request", "requests2", "reqeusts"],
    "urllib3": ["urllib", "urllib2", "urlib3"],
    "yaml": ["yml", "ymle", "pyyaml"],
    "numpy": ["numy", "np", "numpy2"],
    "discord": ["discord.py", "dcord", "discor"],
    "boto3": ["bot3", "boto", "boto33"],
}

def check_pypi_typosquat(package_name, typos):
    """Check if typosquatted versions exist on PyPI"""
    results = []
    for typo in typos:
        url = f"https://pypi.org/project/{typo}/"
        r = requests.head(url, timeout=5, allow_redirects=True)
        if r.status_code == 200:
            results.append(typo)
    return results

def check_npm_typosquat(package_name, typos):
    """Check if typosquatted versions exist on npm"""
    results = []
    for typo in typos:
        url = f"https://registry.npmjs.org/{typo}"
        r = requests.head(url, timeout=5)
        if r.status_code == 200:
            results.append(typo)
    return results

def main():
    print("[*] MCP Dependency — Typosquatting Scanner\n")
    
    findings = []
    
    for pkg, typos in TYPOSQUATTED.items():
        pypi_results = check_pypi_typosquat(pkg, typos)
        npm_results = check_npm_typosquat(pkg, typos)
        
        if pypi_results:
            print(f"[!] PyPI typosquat found for {pkg}: {pypi_results}")
            findings.append(("pypi", pkg, pypi_results))
        if npm_results:
            print(f"[!] npm typosquat found for {pkg}: {npm_results}")
            findings.append(("npm", pkg, npm_results))
    
    if not findings:
        print("[-] No obvious typosquat packages found.")
        print("[*] Note: This checks only common patterns. Manual review of")
        print("    the actual requirements.txt/package.json is recommended.")
    
    return findings

if __name__ == "__main__":
    main()