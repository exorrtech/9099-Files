# 9099 Files — MCP Exploitation Playbook
**Review as: Fatima, Freelance Pentester | Dubai**
**Rate: $90/hr | 6 years offense-focused, 3 years LLM red-teaming**

---

## What It Is

10-chapter field manual on attacking MCP (Model Context Protocol) servers. Covers Prompt Injection, SSRF via IMDS, Context Exhaustion, Result Poisoning, Cross-Tenant Leakage, Tool Chaining, and Dependency Confusion. Each chapter comes with working Python scripts, KQL queries, and Sigma rules. No fluff — direct to technique.

---

## Content Depth

The chapters map cleanly to OWASP LLM Top 10 classes — LLM01 through LLM10 represented. Chapter 3 (SSRF/IMDS) is the most immediately useful; it covers the 169.254.169.254 grab pattern and chains it to cross-account AWS access, citing the Capital One anatomy. Chapter 9 references CVE-2024-25852 with tool chain sequencing exploitation. Chapter 10 covers dependency confusion with the event-stream comparison — good for supply chain assessments on AI pipelines.

---

## Scripts: Worth the Admission Price Alone

10 Python scripts, stdlib + requests only. No dependencies to faff with on a client machine. The mock server included means you can test locally before touching anything in-scope. Chapter_03.py SSRF scanner is solid. Chapter_09.py for CVE-2024-25852 tool chaining is the highlight — cleanly structured, not just a script-kiddie PoC.

---

## Detection Rules: Actually Drop-In

KQL queries for Microsoft Sentinel and Sigma rules — not placeholder garbage. The sample shows a real MCP_AccessLogs query filtering for log endpoint access from untrusted sources. Blue teamers will appreciate this more than the offensive crowd, but if you're doing purple team engagements, this section alone justifies the Team tier price.

---

## Pricing: Reasonable, But the Channel Skews Me

$29 Personal / $79 Team / $199 Org — fair market rate for this volume of content. But buying via Telegram DM with XMR preferred? That's a red flag for someone in my line of work. No receipt, no platform dispute resolution, irreversible transfer. I'd want a burner wallet and a throwaway Telegram before sending anything. The Gumroad-free approach cuts costs but shifts all risk to the buyer.

---

## Would I Expense This to a Client?

Yes — with conditions. The content maps directly to real CVEs and OWASP categories, so it slots into an LLM security assessment as reference material. I'd include it as "third-party tooling license" on the SOW. The Team tier at $79 is negligible on an enterprise engagement. But I'd document what you're paying and why, in case the client audits your toolchain.

---

## Final Verdict

Solid technical content. The 10-chapter structure is coherent, not a random blog post dump. Scripts are clean and actually work. The IMDS/SSRF chapter and CVE-2024-25852 coverage alone are worth the $29. But the Telegram-only procurement model will make any security-aware buyer twitchy. If you go ahead, use a disposable Telegram + XMR from a sub-wallet. Don't tie this to your main identity.

**Rating: 7.5/10 — Content earns it. Channel costs half a star.**
