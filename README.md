# 9099 Files — MCP Exploitation Playbook

> *MCP attack surfaces are largely undocumented. This is the playbook written from the other side of the keyboard.*

---

## What Is This

A 10-chapter field manual for attacking and defending Model Context Protocol servers. Real vulnerabilities. Real exploitation paths. Real PoC code.

Not a blog post. Not a conference slide deck. Offensive research that was verified, documented, and packaged for operators who break things for real.

Each chapter includes:
- Full working PoC code you can run immediately
- Real terminal output showing the attack
- Real CVE/case references
- Detection rules (KQL for Sentinel, Sigma rules)
- Defensive countermeasures that actually work

---

## The 10 Chapters

```
01 — Prompt Injection via Tool Instructions
    Making the model follow embedded instructions from user input.

02 — Permission Escalation
    Using tool scopes to reach what other tools expose.

03 — SSRF / Cloud Metadata Extraction
    Pulling AWS, GCP, and Azure credentials through MCP tools.

04 — Context Exhaustion
    Crashing agents and triggering error-state data leaks.

05 — Result Poisoning
    Making agents trust planted data as if it were real.

06 — Log Leaks
    Where your secrets actually go when the server is logging.

07 — Server Injection
    Persistent access through startup scripts and cron.

08 — Cross-Tenant Leakage
    When tenant isolation breaks and data bleeds between orgs.

09 — Tool Manipulation
    Exploiting the space between tools — chain interception.

10 — Dependency Attacks
    Supply chain exploitation through typosquatting and CVEs.
```

---

## Who It's For

Security researchers who want MCP-specific exploitation research they can actually use. Red teamers running MCP-focused assessments. Blue teamers auditing MCP deployments for the first time. Operators who need to demonstrate real attack paths to clients, not theoretical ones.

---

## Get the Full Playbook

**$29 USDT — one-time payment, yours forever**

```
1. Send $29 USDT (TRC20) to:
   TWWCkDnC1eo1wudKFx2gLBmdkm3hnbFs77

2. Open Telegram → @hunnidinnit

3. Send the TX hash
   File delivered within minutes.
```

No platform account. No Gumroad gate. Direct transfer, direct delivery.

---

## Sample Chapters

- [Chapter 01 — Prompt Injection](docs/chapter-01.md) ← Full chapter, real PoC
- [Chapter 05 — Result Poisoning](docs/chapter-05.md) ← Full chapter, real PoC

The remaining 8 chapters are in the full playbook.

---

## Tools Covered

```bash
# Python scripts included in full playbook:
mcp_prompt_injection.py      # Chapter 01
mcp_escalation.py            # Chapter 02
mcp_ssrf_extraction.py       # Chapter 03
mcp_context_exhaustion.py    # Chapter 04
mcp_result_poisoning.py      # Chapter 05
mcp_log_leak_scanner.py      # Chapter 06
mcp_server_injection.py      # Chapter 07
mcp_cross_tenant.py          # Chapter 08
mcp_tool_manipulation.py     # Chapter 09
mcp_typosquat_checker.py     # Chapter 10
```

---

## The Void Has No Surface to Attack

This is what offensive security looks like when it's not filtered through a marketing team. Ten chapters. Ten real attack paths. Zero theoretical content.

Run the PoCs. Find the vulnerabilities. Build the defenses.

exorr.tech