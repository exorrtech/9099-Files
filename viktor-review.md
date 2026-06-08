# 9099 Files — MCP Exploitation Playbook
## Review by Viktor, DevSecOps Lead, Stockholm SaaS

---

## 1. What It Is

A 10-chapter field manual covering attacks against MCP (Model Context Protocol) servers — the glue layer connecting LLM applications to external tools, RAG pipelines, and cloud IMDS endpoints. Each chapter delivers working PoC code, CVE references, and SIEM-ready detection rules. This is not theoretical research; it is operational tooling for red teamers and security engineers hardening AI stacks.

---

## 2. The Chapters Breakdown

The 10 chapters map to OWASP LLM Top 10 categories:

- **Ch01 — Prompt Injection**: Context override, invisible instruction precedence
- **Ch02 — Permission Escalation**: Auth drift, capability chaining across privilege boundaries
- **Ch03 — SSRF and IMDS**: 169.254.169.254 token grabs, Capital One-style cross-account paths
- **Ch04 — Context Exhaustion**: Token bomb payloads, cost amplification attacks
- **Ch05 — Result Poisoning**: RAG pipeline contamination, tool cache corruption
- **Ch06 — Tool Behavior Leaks**: Timing leaks, log traversal exposing MCP architecture
- **Ch07 — Server-Side Injection**: XSS via tool output propagation
- **Ch08 — Cross-Tenant Leakage**: Shared MCP server as data bridge, RLS gaps
- **Ch09 — Tool Chaining Attacks**: CVE-2024-25852 exploitation
- **Ch10 — Dependency Confusion**: Typosquatting AI tooling packages, npm confusion

---

## 3. Scripts: What You Are Getting

Ten Python scripts — stdlib and requests only. The sample output shows chapter_03.py successfully enumerating GCP metadata endpoints via SSRF through the MCP server. Scripts are described as tested 30x each (300/300 runs, 0 crashes) with a mock server included.

For a DevSecOps lead, these scripts double as detection test cases. Run them in staging, capture the traffic, build your alert logic.

---

## 4. CI/CD Integration Reality Check

Concern: This is a PDF plus Python scripts product. No Docker image, no containerized toolchain, no CI-friendly output format. If you are expecting docker run exploit --target $MCP_URL, that is not here.

The scripts are standalone stdlib Python, which is good — no pip dependencies to poison. But integrating them into a CI pipeline requires wrapping them yourself. For a product at 150+ USD I would expect a Docker-based toolchain with an entrypoint, environment variable config, and structured JSON output for parsing.

What you would need to build: Dockerfile wrapping all 10 scripts, entrypoint with target URL and script selector, JSON output mode for CI log parsing, Helm chart or K8s job manifest for cluster testing.

This is achievable in an afternoon with the current scripts — but it is on you.

---

## 5. Detection Rules: KQL and Sigma

The sample KQL shows Sentinel queries against MCP_AccessLogs for log endpoint access from untrusted sources. The Sigma rules are not shown in the preview but the page claims they are included. This is the most immediately actionable part for blue teamers — drop the queries, tune the baselines, run detection within hours.

For a Stockholm SaaS shop with Azure Sentinel already in place, these rules have real utility. The Chapter 06 log traversal detection is exactly the kind of gap teams miss when rolling out MCP internally.

---

## 6. Pricing Assessment

- Personal: 29 USD
- Team: 79 USD (up to 5 seats)
- Org: 199 USD (unlimited plus future chapters)

The pricing is reasonable for the content volume. However, the Monero and USDT-only P2P payment via Telegram DM is a friction point for corporate procurement. No invoice, no receipt, no company card. For an individual contributor it is fine; for a Swedish company with procurement policies it is an obstacle.

At 199 USD Org tier, if the Sigma rules are complete and the PoC scripts are reliable, this pays for itself in one penetration test engagement versus building equivalent tooling internally.

---

## 7. Operational Security Notes

The product itself is exploitation tooling — not malicious by design, but operationally sensitive. If you are buying this, treat it like any other offensive security tool: access-controlled, not in your public repo, logged who accesses it. The XMR and Telegram payment model is standard for this space but worth noting for compliance tracking.

---

## 8. Decision: Buy or Skip

**Buy if:**
- You are running MCP in production and need offensive coverage to validate defenses
- Your team does red team engagements and needs MCP-specific tooling
- You want the KQL and Sigma rules for Sentinel or Splunk immediately

**Skip or negotiate if:**
- You need Docker-based tooling with CI/CD pipelines baked in — build the wrapper yourself and negotiate on Org pricing
- Corporate procurement requires invoices — the P2P payment model blocks this

For my team: The content is solid, the scripts are stdlib (auditables), and the detection rules are immediately deployable. I would buy the Org tier, build a Docker wrapper over a weekend, and have it integrated into our staging security scans by Monday.

**Rating: 7 out of 10** — High signal content, friction-heavy delivery. The Docker integration gap is the only thing keeping this from a 9.

---

*Review by Viktor, DevSecOps Lead | Stockholm | June 2026*
