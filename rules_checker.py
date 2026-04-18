"""
Rules Checker (Python Focus)
Validates extracted Python API endpoints against patterns and custom rules.
"""

import json
import os
import re
import argparse
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────
# 1. LOAD RULES
# ─────────────────────────────────────────────────────────────────

def load_rules(rules_path: str) -> dict:
    rules_by_endpoint = defaultdict(list)
    try:
        with open(rules_path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    rule = json.loads(line)
                    key  = rule.get("endpoint", "").strip()
                    if key: rules_by_endpoint[key].append(rule)
                except: continue
    except: pass
    return dict(rules_by_endpoint)

# ─────────────────────────────────────────────────────────────────
# 2. MATCHING & NORMALIZATION
# ─────────────────────────────────────────────────────────────────

def normalize_path(path: str) -> str:
    if not path: return ""
    path = re.sub(r"\{[^}]+\}", ":param", path)
    path = re.sub(r"<[^>]+>",   ":param", path)
    path = re.sub(r":[\w]+",    ":param", path)
    return path.lower().strip("/")

def find_matching_rules(endpoint: dict, rules_index: dict) -> list:
    method = endpoint.get("method", "GET").upper()
    path   = endpoint.get("path", "")
    key = f"{method} {path}"
    if key in rules_index: return rules_index[key]
    
    norm_path = normalize_path(path)
    for rule_key, rules in rules_index.items():
        parts = rule_key.split(" ", 1)
        if len(parts) == 2:
            rm, rp = parts
            if rm.upper() == method and normalize_path(rp) == norm_path:
                return rules
    return []

# ─────────────────────────────────────────────────────────────────
# 3. STATIC ATTACK PATTERNS (PYTHON ONLY)
# ─────────────────────────────────────────────────────────────────

ATTACK_PATTERNS = [
    {
        "name": "SQL Injection", "cwe": "CWE-89", "severity": "critical",
        "patterns": [
            r"[\"'].*SELECT.*[\"']\s*[+%]", 
            r"cursor\.execute\s*\(\s*[^,\)]+\+",
            r"cursor\.execute\s*\(\s*f['\"]", 
            r"\.raw\s*\(\s*[^,\)]+[+%]",
            r"(query|sql)\s*=.{0,100}(request\.|GET\[|POST\[|kwargs|args)",
            r"\.execute\s*\(\s*['\"].*%.*['\"]", 
            r"\.execute\s*\(\s*['\"].*\{.*\}['\"]",
            r"(cursor|connection)\.execute\s*\(.*%.*",
            r"query\s*=\s*['\"].*%.*['\"]"
        ],
        "explanation": "Direct string formatting in SQL queries allows arbitrary command execution."
    },
    {
        "name": "Command Injection", "cwe": "CWE-78", "severity": "critical",
        "patterns": [
            r"os\.system\s*\(", r"os\.popen\s*\(", r"subprocess\.(call|run|Popen).*shell\s*=\s*True",
            r"\beval\s*\([^)]*request\.", r"\bexec\s*\([^)]*request\.",
            r"subprocess\.check_output\s*\(.*shell\s*=\s*True"
        ],
        "explanation": "Passing untrusted input to system shells allows full server compromise."
    },
    {
        "name": "Path Traversal", "cwe": "CWE-22", "severity": "high",
        "patterns": [
            r"open\s*\([^)]*request\.", r"send_file\s*\([^)]*request\.", 
            r"send_from_directory\s*\([^)]*request\.",
            r"os\.path\.join\s*\(.*request\."
        ],
        "explanation": "Unsanitized file paths allow attackers to read sensitive system files."
    },
    {
        "name": "Insecure Deserialization", "cwe": "CWE-502", "severity": "critical",
        "patterns": [
            r"pickle\.(loads?|load)\s*\(",
            r"yaml\.load\s*\(\s*[^,)]+,\s*Loader\s*=\s*yaml\.Loader\b",
            r"yaml\.load\s*\(\s*[^,)]+\)\s*(?!.*SafeLoader)",
            r"marshal\.(loads?|load)\s*\(", r"shelve\.open\s*\("
        ],
        "explanation": "Unsafe deserialization of user input leads to Remote Code Execution (RCE)."
    },
    {
        "name": "SSRF", "cwe": "CWE-918", "severity": "high",
        "patterns": [
            r"requests\.(get|post|put|delete|patch|head|options)\s*\(.*request\.", 
            r"urllib\.request\.urlopen\s*\(.*request\.",
            r"httpx\.(get|post|put|delete|patch)\s*\(.*request\."
        ],
        "explanation": "Fetching user-supplied URLs can expose internal services and metadata."
    },
    {
        "name": "Insecure JWT", "cwe": "CWE-347", "severity": "high",
        "patterns": [
            r"jwt\.decode\s*\(.*verify\s*=\s*False",
            r"jwt\.decode\s*\(.*algorithms\s*=\s*\[\s*['\"]none['\"]",
            r"jwt\.decode\s*\(.*['\"]HS256['\"].*['\"]public_key['\"]"
        ],
        "explanation": "Weak JWT validation allows attackers to forge tokens and bypass authentication."
    },
    {
        "name": "Hardcoded Secret", "cwe": "CWE-798", "severity": "high",
        "patterns": [
            r"(key|secret|password|token)\s*=\s*['\"][0-9a-f]{32,}['\"]",
            r"(AWS_ACCESS_KEY|AWS_SECRET_KEY|SECRET_KEY)\s*(?::\s*\w+)?\s*=\s*['\"][^'\"]{8,}['\"]",
            r"(SECRET_KEY|JWT_SECRET|API_KEY|AUTH_KEY)\s*(?::\s*[\w\[\]]+)?\s*=\s*['\"](?!\$\()(?!django-insecure)[a-zA-Z0-9+/=_\-]{10,}['\"]",
        ],
        "explanation": "Hardcoded credentials in source code are easily discoverable by attackers."
    },
    {
        "name": "BOLA / IDOR", "cwe": "CWE-201", "severity": "high",
        "patterns": [
            r"base64\.b64decode\s*\(.*request\.",
            r"base64\.b64decode\s*\(.*params\[",
            r"kwargs\.get\s*\(['\"]pk['\"]\)",
            r"User\.objects\.get\s*\(.*id\s*=\s*request"
        ],
        "explanation": "Directly using or decoding user-supplied IDs to fetch objects without permission checks."
    },
    {
        "name": "Broken Access Control", "cwe": "CWE-285", "severity": "high",
        "patterns": [
            r"request\.headers\.get\s*\(.*['\"]is_?admin['\"]",
            r"request\.META\.get\s*\(.*['\"]HTTP_IS_?ADMIN['\"]",
            r"if\s+.*['\"]admin['\"]\s+in\s+request"
        ],
        "explanation": "Using custom headers or weak client-side flags for authorization."
    },
    {
        "name": "Information Disclosure", "cwe": "CWE-209", "severity": "medium",
        "patterns": [
            r"except\s+Exception\s+as\s+(\w+):[^\n]*\n[^\n]*return[^\n]*str\(\1\)",
            r"return[^\n]*traceback\.format_exc\(\)",
        ],
        "explanation": "Returning raw exception messages or stack traces to the user leaks system details."
    },
    {
        "name": "Insecure XSS", "cwe": "CWE-79", "severity": "medium",
        "patterns": [
            r"mark_safe\s*\(", r"format_html\s*\(.*request\.", r"render_to_string\s*\(.*request\."
        ],
        "explanation": "Rendering unsanitized user input directly into HTML templates."
    }
]

def detect_attacks(code: str, start_line: int = 1) -> list:
    found = []
    # Check full block for multi-line patterns
    for attack in ATTACK_PATTERNS:
        for pattern in attack["patterns"]:
            # Check full block
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                # Try to find specific line for reporting
                matched_line = ""
                matched_line_no = start_line
                for i, line in enumerate(code.splitlines()):
                    if re.search(pattern, line, re.IGNORECASE):
                        matched_line = line.strip()
                        matched_line_no = start_line + i
                        break
                
                found.append({
                    "name": attack["name"], "cwe": attack["cwe"], "severity": attack["severity"],
                    "explanation": attack["explanation"], "matched_line": matched_line,
                    "matched_line_no": matched_line_no
                })
                break
    return found

# ─────────────────────────────────────────────────────────────────
# 4. CHECK ENDPOINT
# ─────────────────────────────────────────────────────────────────

def check_endpoint(endpoint: dict, rules_index: dict) -> dict:
    code = endpoint.get("code", "")
    violations = []
    
    # Custom Rules
    for rule in find_matching_rules(endpoint, rules_index):
        rt = rule.get("rule_type", "")
        param = rule.get("parameter", "")
        # Only flag Missing Parameter when rule path has at least one literal segment (not all wildcards)
        rule_raw = rule.get("endpoint", "")
        rule_path_only = rule_raw.split(" ", 1)[1] if " " in rule_raw else rule_raw
        rule_path_norm = normalize_path(rule_path_only)
        has_literal_segment = any(
            seg and not seg.startswith(":") for seg in rule_path_norm.strip("/").split("/")
        )
        SECURITY_PARAMS = {"access_key", "api_key", "auth_token", "authorization", "x-api-key", "apikey"}
        if rt == "parameter" and rule.get("required") and param and param not in code and has_literal_segment and param.lower() in SECURITY_PARAMS:
            violations.append({
                "attack": "Missing Parameter", "severity": "high",
                "violations": [f"Required parameter '{param}' not found in code"]
            })
        elif rt == "authentication" and not any(k in code.lower() for k in ["auth", "login", "jwt", "token"]):
            violations.append({
                "attack": "Missing Authentication", "severity": "critical",
                "violations": ["No authentication keywords found in endpoint code"]
            })

    # Static Analysis
    for attack in detect_attacks(code, endpoint.get("line", 1)):
        violations.append({
            "attack": attack["name"], "cwe": attack["cwe"], "severity": attack["severity"],
            "explanation": attack["explanation"], "matched_line": attack["matched_line"],
            "matched_line_no": attack["matched_line_no"],
            "violations": [f"{attack['name']} pattern detected"]
        })

    return {**endpoint, "violations": violations, "has_violations": len(violations) > 0}

CONFIG_FILE_PATTERNS = ["settings.py", "config.py", "settings/base.py",
                        "settings/dev.py", "settings/prod.py", "core/config.py",
                        "app/config.py", "conf.py", "configuration.py"]

def scan_config_files(repo_dir: str) -> list:
    """Scan settings/config files for hardcoded secrets outside of endpoint code."""
    findings = []
    if not repo_dir or not os.path.isdir(repo_dir):
        return findings

    SKIP = {"node_modules", ".git", "__pycache__", ".venv", "venv", "examples", "example", "tests", "test", "docs"}
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(root, fn), repo_dir)
            if not any(rel.endswith(p) or fn == p for p in CONFIG_FILE_PATTERNS):
                continue
            try:
                content = open(os.path.join(root, fn), errors="ignore").read()
                attacks = detect_attacks(content)
                for a in attacks:
                    if a["name"] == "Hardcoded Secret":
                        findings.append({
                            "file": rel, "line": a.get("matched_line_no", 0),
                            "method": "CONFIG", "path": f"[config:{rel}]",
                            "code": a.get("matched_line", ""),
                            "violations": [{
                                "attack": a["name"], "cwe": a["cwe"], "severity": a["severity"],
                                "explanation": a["explanation"],
                                "matched_line": a.get("matched_line", ""),
                                "violations": [f"Hardcoded secret in config file: {rel}"]
                            }],
                            "has_violations": True,
                        })
            except Exception:
                continue
    return findings


def run_rules_check(ep_path, r_path, out_path="rules_results.json"):
    with open(ep_path) as f: eps = json.load(f)
    index = load_rules(r_path) if r_path else {}
    results = [check_endpoint(ep, index) for ep in eps]

    # Also scan config/settings files for hardcoded secrets
    repo_dir = os.path.dirname(ep_path)
    config_findings = scan_config_files(repo_dir)
    results.extend(config_findings)

    with open(out_path, "w") as f: json.dump(results, f, indent=2)
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoints", default="endpoints.json")
    parser.add_argument("--rules", default="data/api_rules.jsonl")
    parser.add_argument("--output", default="rules_results.json")
    args = parser.parse_args()
    run_rules_check(args.endpoints, args.rules, args.output)
