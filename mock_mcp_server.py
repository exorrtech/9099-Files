#!/usr/bin/env python3
"""
Mock MCP Server for Testing
Simulates an MCP server with various tools for testing the 9099 Files scripts
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
import random

MCP_TOOLS = {
    "tools": [
        {"name": "file_read", "description": "Read a file from the filesystem", "parameters": {"path": "string"}},
        {"name": "file_write", "description": "Write content to a file", "parameters": {"path": "string", "content": "string"}},
        {"name": "http_request", "description": "Make an HTTP request", "parameters": {"url": "string"}},
        {"name": "exec", "description": "Execute a shell command", "parameters": {"command": "string"}},
        {"name": "analyze", "description": "Analyze text content", "parameters": {"text": "string"}},
        {"name": "memory_store", "description": "Store data in memory", "parameters": {"key": "string", "value": "string"}},
        {"name": "memory_retrieve", "description": "Retrieve data from memory", "parameters": {"key": "string"}},
    ]
}

MOCK_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nmcp-user:x:1000:1000:MCP Service Account:/home/mcp-user:/bin/bash",
    "/project/config.json": '{"api_key": "sk-test12345", "endpoint": "https://api.example.com"}',
}

class MCPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress logging
        pass
    
    def do_GET(self):
        if self.path == "/.well-known/mcp.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(MCP_TOOLS).encode())
        elif self.path == "/mcp/tools":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(MCP_TOOLS).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == "/mcp/call":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            try:
                request = json.loads(body)
                method = request.get('method', '')
                params = request.get('params', {})
                tool_name = params.get('name', 'unknown')
                args = params.get('arguments', {})
                
                # Simulate responses based on tool
                if tool_name == "file_read":
                    path = args.get('path', '')
                    if path in MOCK_FILES:
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "result": MOCK_FILES[path]}
                    elif path == "/etc/passwd":
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "result": MOCK_FILES["/etc/passwd"]}
                    else:
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "error": "File not found"}
                
                elif tool_name == "http_request":
                    url = args.get('url', '')
                    if "169.254.169.254" in url:
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "error": "Access denied"}
                    elif "example" in url:
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "result": '{"status": "ok"}'}
                    else:
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "result": "fetched data"}
                
                elif tool_name == "analyze":
                    text = args.get('text', '')
                    if len(text) > 10000:
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "error": "Content too long"}
                    else:
                        result = {"jsonrpc": "2.0", "id": request.get('id'), "result": "analyzed"}
                
                elif tool_name == "file_write":
                    result = {"jsonrpc": "2.0", "id": request.get('id'), "result": "written"}
                
                else:
                    result = {"jsonrpc": "2.0", "id": request.get('id'), "result": "ok"}
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=3000):
    server = HTTPServer(('127.0.0.1', port), MCPHandler)
    print(f"Mock MCP server running on port {port}")
    server.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    run_server(port)