# 9099 Files: MCP Exploitation Playbook

Offensive security research on Model Context Protocol attack surfaces. 19 chapters, 20 working scripts, detection rules you can drop into a SIEM today.

## What you get

Nineteen chapters. Each covers one attack class against MCP servers: prompt injection, permission escalation, SSRF, context exhaustion, result poisoning, log leaks, server-side injection, cross-tenant leakage, tool chaining, tool poisoning and rug pulls, zero-click injection via connectors, OAuth confused deputy, insecure dev endpoints, malicious server distribution, session hijacking, cross-connector exfiltration chains, schema poisoning, RAG corpus poisoning, and code execution sandbox escape.

Every chapter ships the same way: the full technique, a Python script that runs against the included lab server, and detection rules (KQL for Sentinel, Sigma for everything else). Scripts use stdlib and requests only. No pip install. Run them from an engagement machine as-is.

CVE references are verified against NVD and OSV. Eight real CVEs are anchored to the chapters where they actually apply, from EchoLeak (CVE-2025-32711) to mcp-remote (CVE-2025-6514) to Langflow (CVE-2025-3248). No padding tags.

Two chapters are free. Full chapters, full scripts. Read them before you pay for anything: Chapter 1 and Chapter 10, both PDFs in this repo.

## Verification

test_harness.py starts the lab server and runs every script 30 times. The landing page only quotes numbers that harness actually printed. Run it yourself on day one.

## Pricing

Free $0: two full sample chapters, two sample scripts, the lab server, the harness. It is this repository.

Personal $29: all 19 chapters, 19 scripts, lab server, KQL and Sigma rules. One buyer, personal use.

Team $79: everything in Personal, up to 5 seats, detection rule tuning guide, priority Telegram support.

Org $199: everything in Team, unlimited seats, 12 months of chapter updates, one 30 minute consultation call, audit report template.

Payment is crypto only (XMR preferred, USDT TRC20 accepted). Invoice is a payment receipt with transaction ID. That is what a one-person operation can honestly offer. If your procurement team needs a company invoice with a VAT number, this product is not for you, and pretending otherwise would waste both our time.

## Buy

DM @hunnidinnit on Telegram. Private repo access within 24 hours of payment. 7 day refund if the content does not match what this page describes.

## Author

One engineer. Azure and AI security. The techniques in this playbook come from my own research and engagements, documented so defenders get them too. More at exorr.tech.
