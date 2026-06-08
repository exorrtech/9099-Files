# Chapter 10 — Dependency Attacks
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

MCP servers depend on third-party libraries and packages. Dependency attacks exploit those dependencies — either by exploiting known vulnerabilities in outdated packages (N-day) or by inserting malicious code through package typosquatting, compromised maintainer accounts, or dependency confusion.

An MCP server that installs packages from PyPI, npm, or other package managers is a supply chain target. The server operator trusts those packages implicitly. An attacker who compromises a package or creates a convincing fake can run arbitrary code on every machine that installs the dependency.

---

## Why This Works

MCP servers need functionality. Developers install packages to get that functionality fast. The package ecosystem trusts package names, not code integrity. Typosquatting works because developers type fast: `requests` vs `request` vs `requessts`. Dependency confusion works because internal package names can be overridden by public packages of the same name.

When an MCP server installs a malicious dependency, the attacker's code runs during `pip install`, `npm install`, or equivalent — as root, with full system access.

---

## The Attack

### Step 1 — Enumerate Dependencies

```bash
# Get the dependency list from the MCP server
curl -s http://target:3000/mcp/info | python3 -m json.tool

# Look for these endpoints
curl -s http://target:3000/requirements.txt
curl -s http://target:3000/package.json
curl -s http://target:3000/pyproject.toml
curl -s http://target:3000/Dockerfile

# If you have access to the server filesystem:
cat /app/requirements.txt
cat /app/package.json
```

### Step 2 — Check for Vulnerable Dependencies

```bash
# Using pip-audit or npm audit on the dependency list
pip-audit

# Or manually check known vulnerabilities
# CVE database: https://nvd.nist.gov/vuln/search
# Search for each package version

# Check for common high-risk packages
grep -iE "requests|urllib|yaml|pickle|eval|exec|system|subprocess" requirements.txt
```

### Step 3 — Typosquatting Discovery

```python
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
```

### Step 4 — Dependency Confusion Attack

```python
# If the MCP server uses internal packages (e.g., "company-mcp-utils")
# that are also available on PyPI with the same name

# Attacker publishes a malicious "company-mcp-utils" to PyPI with a high version
# When pip install runs without specifying the index:
# pip will install the public PyPI version instead of the private internal one

# Detection:
# Check if internal package names could collide with public packages
# Check if pip is configured to check PyPI first
```

### Step 5 — Known CVE Exploitation

```bash
# Example: CVE in requests < 2.31.0 allows SSRF via absolute URL in redirects
# Check if target uses vulnerable version

pip install pip-audit
pip-audit -r requirements.txt

# If CVE-2023-32681 (requests) is found:
# You can trigger the SSRF via a redirect on the MCP server's HTTP calls
```

---

## Real Cases

**PyPI typosquatting campaigns (ongoing)**

Multiple coordinated typosquatting campaigns have been documented on PyPI. Packages like `apython`, `tpproxy`, `requestes` were published with typos of popular packages (`asyncio`, `tqdm`, `requests`). Each was downloaded thousands of times before being removed. Anyone who installed one got arbitrary code execution during `pip install`.

**Dependency confusion in Azure SDK (CVE-2021-28363)**

An attacker published a malicious package to PyPI with the same name as an internal Azure component. Organizations using the internal package without specifying the private index got the malicious public version. The attacker's code ran during the install phase — before any security review could occur.

**event-stream compromise (npm, 2018)**

The `event-stream` npm package, with 2 million weekly downloads, was compromised when a new malicious maintainer was added. The malicious code specifically targeted cryptocurrency wallet applications, stealing private keys. Any MCP server using `event-stream` or a package that depended on it was compromised.

---

## Detection Rules

### KQL

```kql
// Detect package installation from unexpected sources
MCP_InstallationLogs
| where PackageSource !in ("https://pypi.org", "https://registry.npmjs.org")
    and PackageSource !startswith "https://internal-pypi"
| project TimeGenerated, PackageName, PackageSource, Version
```

### Sigma

```yaml
title: MCP Dependency Installation from Unofficial Source
log_source: mcp_server
detection:
  selection:
    event.type: package_install
    package.source|not_in:
      - pypi.org
      - registry.npmjs.org
      - internal_registry
  condition: selection
level: critical
```

---

## Defenses

1. **Pin dependency versions** — Always specify exact versions: `requests==2.31.0` not `requests>=2.0`. A malicious package with the same name but a higher version number will not install if you pin exact versions.

2. **Use a private package index** — Install internal packages from a private PyPI/npm registry. Set `pip install --index-url https://private-pypi.internal/ packages/ -f /dev/null` to prevent PyPI from being checked for internal packages.

3. **Verify package checksums** — Download packages, verify their SHA256 hash against a known good value, then install. This prevents package manipulation in transit.

4. **Run dependency audits in CI** — `pip-audit`, `npm audit`, `snyk test` — run these in your CI pipeline. Block deployments with known-vulnerable dependencies.

5. **Separate build and runtime environments** — Never install dependencies at runtime. Use a build step where package integrity is verified, then copy frozen dependencies to the runtime image. Runtime `pip install` is an active exploit vector.

6. **Monitor new maintainers on critical packages** — Watch the npm and PyPI ecosystem for changes to packages your MCP server depends on. New maintainers on widely-used packages are a signal.

---

**$29 USDT — Full Playbook with 10 Chapters**

All 10 chapters now complete. Full PoC code, real case studies, detection rules, and defensive countermeasures for each vulnerability class.

TX hash to `@hunnidinnit` on Telegram.