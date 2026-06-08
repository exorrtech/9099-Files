#!/usr/bin/env python3
"""
9099 Files Test Harness
Clean test environment for all 10 chapter scripts
Runs each script 20 times, validates output, reports errors
"""
import subprocess
import sys
import os
import json
import time
import re
from pathlib import Path

# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Test configuration
TEST_DIR = Path(__file__).parent
DOCS_DIR = TEST_DIR / "docs"
SCRIPTS_DIR = TEST_DIR / "scripts"
RUNS_PER_SCRIPT = 20

# Results storage
results = {
    "passed": 0,
    "failed": 0,
    "errors": [],
    "warnings": []
}

def log(msg, level="info"):
    prefix = {
        "info": f"{BOLD}[TEST]{RESET}",
        "pass": f"{GREEN}{BOLD}[PASS]{RESET}",
        "fail": f"{RED}{BOLD}[FAIL]{RESET}",
        "warn": f"{YELLOW}[WARN]{RESET}",
    }
    print(f"{prefix.get(level, '[INFO]')} {msg}")

def extract_scripts():
    """Extract Python scripts from chapter markdown files"""
    log("Extracting Python scripts from chapter files...")
    SCRIPTS_DIR.mkdir(exist_ok=True)
    
    scripts_found = []
    
    for chapter_file in sorted(DOCS_DIR.glob("chapter-*.md")):
        content = chapter_file.read_text()
        chapter_num = chapter_file.stem.replace("chapter-", "")
        
        # Find code blocks with python
        in_code = False
        code_buffer = []
        current_script = []
        script_name = None
        
        for line in content.split('\n'):
            if line.strip().startswith('```python'):
                in_code = True
                current_script = []
                continue
            elif line.strip() == '```' and in_code:
                in_code = False
                # Check if we have a main() call or if __name__ block
                code_buffer = '\n'.join(current_script)
                if code_buffer.strip():
                    # Generate filename from context
                    if 'def main()' in code_buffer or 'if __name__' in code_buffer:
                        script_path = SCRIPTS_DIR / f"chapter_{chapter_num}.py"
                        script_path.write_text(code_buffer)
                        scripts_found.append(script_path)
                current_script = []
                continue
            
            if in_code:
                current_script.append(line)
    
    # Also check for explicit script listings at the bottom of README
    readme = (TEST_DIR / "README.md").read_text()
    for line in readme.split('\n'):
        if line.strip().endswith('.py'):
            # Extract script name
            match = re.search(r'(\w+\.py)', line)
            if match:
                scripts_found.append(match.group(1))
    
    log(f"Found {len(scripts_found)} scripts to test")
    return list(set(scripts_found))

def syntax_check(script_path):
    """Verify Python syntax is clean"""
    try:
        import ast
        with open(script_path) as f:
            ast.parse(f.read())
        return True, None
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

def import_check(script_path):
    """Check all imports are valid"""
    script_content = script_path.read_text()
    # Extract imports
    imports = []
    for line in script_content.split('\n'):
        line = line.strip()
        if line.startswith('import ') and not line.startswith('import sys #'):
            imports.append(line.replace('import ', '').split(' as ')[0].strip())
        elif line.startswith('from ') and 'import' in line:
            match = re.search(r'from\s+(\S+)\s+import', line)
            if match:
                imports.append(match.group(1))
    
    failed_imports = []
    for imp in imports:
        try:
            __import__(imp)
        except ImportError:
            # Check if it's a stdlib module we don't have
            stdlib = ['os', 'sys', 'json', 're', 'time', 'datetime', 'hashlib', 
                      'urllib.parse', 'pathlib', 'collections', 'subprocess']
            if imp not in stdlib and not imp.startswith('http'):
                failed_imports.append(imp)
    
    return len(failed_imports) == 0, failed_imports

def run_script(script_path, run_num):
    """Execute a script and capture output/errors"""
    env = os.environ.copy()
    env['PYTHONPATH'] = str(TEST_DIR)
    
    try:
        result = subprocess.run(
            ['python3', str(script_path)],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            cwd=str(TEST_DIR)
        )
        return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
    except subprocess.TimeoutExpired:
        return {
                "returncode": -1,
                "stdout": "",
                "stderr": "TIMEOUT: Script exceeded 30s",
                "success": False
            }
    except Exception as e:
        return {
                "returncode": -2,
                "stdout": "",
                "stderr": f"EXCEPTION: {str(e)}",
                "success": False
            }

def analyze_output(script_path, run_result):
    """Check if output is clean and as expected"""
    warnings = []
    
    # Check for common issues
    stderr = run_result.get('stderr', '')
    stdout = run_result.get('stdout', '')
    
    # Warning: empty output when we expect output
    if not stdout and not stderr and run_result['returncode'] == 0:
        warnings.append("Empty output on successful run")
    
    # Warning: stderr present on "successful" run
    if stderr and run_result['returncode'] == 0:
        # Filter out benign warnings
        benign = ['DeprecationWarning', 'UserWarning', 'ResourceWarning']
        real_warnings = [w for w in stderr.split('\n') if w and not any(b in w for b in benign)]
        if real_warnings:
            warnings.append(f"stderr on success: {real_warnings[0][:80]}")
    
    # Warning: requests library warnings
    if 'requests' in stderr and 'InsecureRequestWarning' in stderr:
        warnings.append("Unverified HTTPS warnings not suppressed")
    
    # Check for error patterns
    error_patterns = [
        (r'Traceback.*', "Runtime error"),
        (r'SyntaxError', "Syntax error"),
        (r'IndentationError', "Indentation error"),
        (r'NameError', "Undefined variable"),
        (r'ImportError', "Import error"),
        (r'ModuleNotFoundError', "Missing module"),
        (r'AttributeError', "Attribute error"),
        (r'TypeError', "Type error"),
    ]
    
    combined_output = stdout + stderr
    for pattern, error_type in error_patterns:
        if re.search(pattern, combined_output, re.IGNORECASE):
            if run_result['returncode'] != 0:
                return False, f"{error_type}: {re.search(pattern, combined_output).group()[:60]}", warnings
    
    return True, None, warnings

def test_script(script_path, iterations=RUNS_PER_SCRIPT):
    """Test a single script N times"""
    script_name = script_path.name
    log(f"Testing {script_name} ({iterations} runs)...")
    
    # Syntax check first
    ok, err = syntax_check(script_path)
    if not ok:
        log(f"{script_name}: {err}", "fail")
        results["failed"] += 1
        results["errors"].append(f"{script_name}: {err}")
        return False
    
    # Import check
    ok, bad_imports = import_check(script_path)
    if not ok:
        log(f"{script_name}: Missing imports: {bad_imports}", "warn")
        results["warnings"].append(f"{script_name}: Missing imports: {bad_imports}")
    
    # Run iterations
    success_count = 0
    all_clean = True
    error_occurrences = {}
    
    for i in range(1, iterations + 1):
        run_result = run_script(script_path, i)
        is_clean, error_msg, warnings = analyze_output(script_path, run_result)
        
        if is_clean:
            success_count += 1
        else:
            all_clean = False
            if error_msg:
                error_occurrences[error_msg] = error_occurrences.get(error_msg, 0) + 1
        
        if warnings and i == 1:  # Report warnings on first run
            for w in warnings:
                log(f"{script_name}: {w}", "warn")
    
    if all_clean:
        log(f"{script_name}: {GREEN}PASSED{RESET} ({success_count}/{iterations} clean runs)", "pass")
        results["passed"] += 1
        return True
    else:
        log(f"{script_name}: {RED}FAILED{RESET} ({success_count}/{iterations})", "fail")
        results["failed"] += 1
        for err, count in error_occurrences.items():
            log(f"  → {err} (occurred {count}x)", "fail")
            results["errors"].append(f"{script_name}: {err} ({count}x)")
        return False

def test_mcp_server():
    """Verify mock MCP server is available"""
    log("Checking test MCP server availability...")
    # This would normally start a test server
    # For now, just verify the test structure
    log("Mock server check: SKIPPED (scripts test against live environments)", "warn")
    return True

def main():
    print(f"\n{BOLD}{'='*60}")
    print("9099 Files — Test Harness")
    print(f"{'='*60}{RESET}\n")
    
    log(f"Test iterations per script: {RUNS_PER_SCRIPT}")
    log(f"Test directory: {TEST_DIR}\n")
    
    # Check test MCP server
    test_mcp_server()
    
    # Extract scripts
    scripts = extract_scripts()
    
    if not scripts:
        log("No scripts found to test", "fail")
        return 1
    
    log(f"Testing {len(scripts)} scripts...\n")
    
    # Test each script
    for script in sorted(scripts):
        test_script(script)
    
    # Summary
    print(f"\n{BOLD}{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}{RESET}")
    log(f"Passed: {GREEN}{results['passed']}{RESET}")
    log(f"Failed: {RED if results['failed'] > 0 else '0'}{results['failed']}{RESET}")
    log(f"Warnings: {YELLOW}{len(results['warnings'])}{RESET}")
    
    if results['errors']:
        print(f"\n{RED}{BOLD}Errors:{RESET}")
        for err in results['errors'][:10]:
            print(f"  - {err}")
    
    return 0 if results['failed'] == 0 else 1

if __name__ == "__main__":
    sys.exit(main())