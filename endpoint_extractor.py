import os
import re
import json
import argparse
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────
# 1. DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    file:          str
    line:          int
    method:        str
    path:          str
    code:          str
    language:      str
    framework:     str
    function_name: str = ""


@dataclass
class RepoContext:
    """
    Cross-file context built during the pre-scan phase.
    """
    # Flask Blueprint: var_name → url_prefix
    flask_bp_prefixes:   Dict[str, str] = field(default_factory=dict)

    # FastAPI APIRouter: var_name → prefix
    fastapi_prefixes:    Dict[str, str] = field(default_factory=dict)

    # Raw file content: rel_path → content string
    contents:            Dict[str, str] = field(default_factory=dict)

    # Repo root (set after init)
    repo_dir:            str = ""


# ─────────────────────────────────────────────────────────────────
# 2. UTILITIES
# ─────────────────────────────────────────────────────────────────

def normalize_path(prefix: str, path: str) -> str:
    """Join a URL prefix and a relative path cleanly."""
    prefix = (prefix or "").rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return prefix + path


def extract_code_block(lines: list, start: int, max_lines: int = 250) -> str:
    """
    Extract a function/handler code block starting at `start`.
    Uses indentation tracking for Python.
    """
    block = []
    indent = None
    
    # Capture the starting line
    first_line = lines[start]
    block.append(first_line)
    
    # Calculate base indentation from the first line with content after the start
    for i in range(start + 1, min(start + max_lines, len(lines))):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped:
            block.append(line)
            continue
            
        curr_indent = len(line) - len(stripped)
        if indent is None:
            indent = curr_indent
            
        # If we hit a line with less indentation than our block, stop
        if curr_indent < indent and stripped:
            break
        block.append(line)

    return "".join(block).strip()


# ─────────────────────────────────────────────────────────────────
# 3. PRE-SCAN PHASE
# ─────────────────────────────────────────────────────────────────

def _prescan_python(content: str, rel_path: str, ctx: RepoContext) -> None:
    """Collect Flask Blueprint and FastAPI APIRouter prefixes."""

    # Flask: bp = Blueprint('name', __name__, url_prefix='/x')
    for m in re.finditer(
        r"(\w+)\s*=\s*Blueprint\s*\([^)]*url_prefix\s*=\s*['\"]([^'\"]+)['\"]",
        content,
    ):
        ctx.flask_bp_prefixes[m.group(1)] = m.group(2)

    # Flask: app.register_blueprint(bp, url_prefix='/x')
    for m in re.finditer(
        r"register_blueprint\s*\(\s*(\w+)[^)]*url_prefix\s*=\s*['\"]([^'\"]+)['\"]",
        content,
    ):
        ctx.flask_bp_prefixes[m.group(1)] = m.group(2)

    # FastAPI: router = APIRouter(prefix='/x')
    for m in re.finditer(
        r"(\w+)\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*['\"]([^'\"]+)['\"]",
        content,
    ):
        ctx.fastapi_prefixes[m.group(1)] = m.group(2)

    # FastAPI: app.include_router(router, prefix='/x')
    for m in re.finditer(
        r"include_router\s*\(\s*(\w+)[^)]*prefix\s*=\s*['\"]([^'\"]+)['\"]",
        content,
    ):
        ctx.fastapi_prefixes[m.group(1)] = m.group(2)


def prescan_repo(repo_dir: str) -> RepoContext:
    """
    First pass: walk all repo files and build the global RepoContext.
    """
    ctx = RepoContext(repo_dir=repo_dir)

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            if not filename.endswith(".py"):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, repo_dir)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                ctx.contents[rel_path] = content
                _prescan_python(content, rel_path, ctx)
            except Exception:
                continue

    return ctx


# ─────────────────────────────────────────────────────────────────
# 4. PYTHON EXTRACTORS
# ─────────────────────────────────────────────────────────────────

def extract_flask(content: str, filepath: str, ctx: RepoContext) -> list:
    endpoints = []
    lines = content.splitlines(keepends=True)

    for i, line in enumerate(lines):
        m = re.search(
            r"@(\w+)\.route\(['\"]([^'\"]+)['\"]"
            r"(?:.*?methods=\[([^\]]+)\])?",
            line,
        )
        if m:
            var_name    = m.group(1)
            path        = m.group(2)
            methods_raw = m.group(3) or "'GET'"
            methods     = re.findall(r"['\"](\w+)['\"]", methods_raw) or ["GET"]
            prefix      = ctx.flask_bp_prefixes.get(var_name, "")
            full_path   = normalize_path(prefix, path)

            fn_name = ""
            for j in range(i + 1, min(i + 4, len(lines))):
                fn_m = re.search(r"def\s+(\w+)\s*\(", lines[j])
                if fn_m:
                    fn_name = fn_m.group(1)
                    break
            code = extract_code_block(lines, i)
            for method in methods:
                endpoints.append(Endpoint(
                    file=filepath, line=i + 1, method=method.upper(),
                    path=full_path, code=code, language="Python",
                    framework="Flask", function_name=fn_name,
                ))
            continue

        m = re.search(
            r"@(\w+)\.(get|post|put|delete|patch)\s*\(['\"]([^'\"]+)['\"]\)",
            line, re.IGNORECASE,
        )
        if m:
            var_name  = m.group(1)
            method    = m.group(2).upper()
            path      = m.group(3)
            prefix    = ctx.flask_bp_prefixes.get(var_name, "")
            full_path = normalize_path(prefix, path)

            fn_name = ""
            for j in range(i + 1, min(i + 4, len(lines))):
                fn_m = re.search(r"def\s+(\w+)\s*\(", lines[j])
                if fn_m:
                    fn_name = fn_m.group(1)
                    break
            code = extract_code_block(lines, i)
            endpoints.append(Endpoint(
                file=filepath, line=i + 1, method=method,
                path=full_path, code=code, language="Python",
                framework="Flask", function_name=fn_name,
            ))
            continue

    return endpoints


def extract_fastapi(content: str, filepath: str, ctx: RepoContext) -> list:
    endpoints = []
    lines = content.splitlines(keepends=True)

    local_prefixes: Dict[str, str] = {}
    for m in re.finditer(r"(\w+)\s*=\s*APIRouter\s*\(", content):
        local_prefixes[m.group(1)] = ""

    for m in re.finditer(
        r"(\w+)\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*['\"]([^'\"]+)['\"]",
        content,
    ):
        local_prefixes[m.group(1)] = m.group(2)

    effective_prefixes = {**ctx.fastapi_prefixes, **local_prefixes}

    i = 0
    while i < len(lines):
        line = lines[i]

        # Single-line decorator: @router.get("/path", ...)
        m = re.search(
            r"@(\w+)\.(get|post|put|delete|patch|options)\s*\(\s*['\"]([^'\"]+)['\"]",
            line, re.IGNORECASE,
        )

        if not m:
            # Multi-line decorator: @router.get(\n    "/path",\n    ...)
            ml = re.search(r"@(\w+)\.(get|post|put|delete|patch|options)\s*\(", line, re.IGNORECASE)
            if ml:
                window = "".join(lines[i: i + 6])
                m = re.search(
                    r"@(\w+)\.(get|post|put|delete|patch|options)\s*\(\s*['\"]([^'\"]+)['\"]",
                    window, re.IGNORECASE | re.DOTALL,
                )

        if m:
            var_name  = m.group(1)
            method    = m.group(2).upper()
            path      = m.group(3)
            prefix    = effective_prefixes.get(var_name, "")
            full_path = normalize_path(prefix, path)

            fn_name = ""
            for j in range(i + 1, min(i + 8, len(lines))):
                fn_m = re.search(r"(?:async\s+)?def\s+(\w+)\s*\(", lines[j])
                if fn_m:
                    fn_name = fn_m.group(1)
                    break
            code = extract_code_block(lines, i)
            endpoints.append(Endpoint(
                file=filepath, line=i + 1, method=method,
                path=full_path, code=code, language="Python",
                framework="FastAPI", function_name=fn_name,
            ))

        i += 1

    return endpoints


def extract_django(content: str, filepath: str, ctx: RepoContext) -> list:
    endpoints = []
    if not (filepath.endswith("urls.py") or "urlpatterns" in content):
        return endpoints

    lines = content.splitlines(keepends=True)
    for i, line in enumerate(lines):
        # Filter out common Django "noise" routes
        if any(x in line for x in ["admin.site.urls", "static(", "settings.STATIC_URL", "include('debug_toolbar')"]):
            continue

        # Pattern 1: path('...', views.my_view) or url(r'^...', views.my_view)
        # Supports: as_view() calls
        m = re.search(
            r"(?:path|url|re_path)\s*\(\s*[r]?['\"]([^'\"]+)['\"]\s*,\s*([\w\.]+)(?:\.as_view\s*\()?",
            line,
        )
        
        # Pattern 2: router.register(r'path', views.ViewSet)
        is_router = False
        if not m:
            m = re.search(r"router\.register\s*\(\s*[r]?['\"]([^'\"]+)['\"]\s*,\s*([\w\.]+)", line)
            is_router = True

        if not m: continue

        raw_path = m.group(1)
        view_ref = m.group(2)
        
        if any(p in raw_path.lower() for p in ["admin/", "swagger", "redoc", "favicon"]):
            continue

        clean = re.sub(r"[\\^$]", "", raw_path)
        clean = re.sub(r"\(\?P<\w+>[^)]+\)", "{param}", clean)
        clean = clean.rstrip("/") or "/"
        if not clean.startswith("/"): clean = "/" + clean

        view_func_name = view_ref.split(".")[-1]
        view_code = line.strip()
        found_code = False
        
        for rel_path, file_content in ctx.contents.items():
            if view_func_name in file_content:
                f_lines = file_content.splitlines(keepends=True)
                for k, f_line in enumerate(f_lines):
                    if re.search(rf"def\s+{view_func_name}\s*\(", f_line):
                        view_code = extract_code_block(f_lines, k)
                        found_code = True
                        break
                    if re.search(rf"class\s+{view_func_name}\s*\(", f_line):
                        view_code = extract_code_block(f_lines, k, max_lines=300)
                        found_code = True
                        break
            if found_code: break

        methods = ["GET"]
        view_l = view_code.lower()
        if "post(" in view_l or "def post" in view_l or "request.post" in view_l: methods.append("POST")
        if "put(" in view_l or "def put" in view_l: methods.append("PUT")
        if "delete(" in view_l or "def delete" in view_l: methods.append("DELETE")
        if "patch(" in view_l or "def patch" in view_l: methods.append("PATCH")

        if is_router:
            # Routers usually imply multiple methods
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

        for method in set(methods):
            endpoints.append(Endpoint(
                file=filepath, line=i + 1, method=method.upper(),
                path=clean, code=view_code, language="Python",
                framework="Django", function_name=view_func_name,
            ))

    return endpoints


# ─────────────────────────────────────────────────────────────────
# 5. FILE ROUTER & WALKER
# ─────────────────────────────────────────────────────────────────

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__",
    ".venv", "venv", "env", "dist", "build",
}

def extract_add_api_route(content: str, filepath: str, ctx: RepoContext) -> list:
    """Handle FastAPI app.add_api_route('/path', handler, methods=['GET']) pattern."""
    endpoints = []
    lines = content.splitlines(keepends=True)

    all_prefixes = {**ctx.fastapi_prefixes}
    for m in re.finditer(r"(\w+)\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*['\"]([^'\"]+)['\"]", content):
        all_prefixes[m.group(1)] = m.group(2)
    for m in re.finditer(r"(\w+)\s*=\s*APIRouter\s*\(", content):
        if m.group(1) not in all_prefixes:
            all_prefixes[m.group(1)] = ""

    for i, line in enumerate(lines):
        m = re.search(
            r"(\w+)\.add_api_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,[^,)]+(?:,\s*methods\s*=\s*\[([^\]]+)\])?",
            line, re.IGNORECASE,
        )
        if m:
            var_name    = m.group(1)
            path        = m.group(2)
            methods_raw = m.group(3) or "'GET'"
            methods     = re.findall(r"['\"](\w+)['\"]", methods_raw) or ["GET"]
            prefix      = all_prefixes.get(var_name, "")
            full_path   = normalize_path(prefix, path)

            for method in methods:
                endpoints.append(Endpoint(
                    file=filepath, line=i + 1, method=method.upper(),
                    path=full_path, code=line.strip(), language="Python",
                    framework="FastAPI", function_name="",
                ))
    return endpoints


def extract_from_file(filepath: str, content: str, ctx: RepoContext) -> list:
    endpoints = []
    if not filepath.endswith(".py"):
        return endpoints

    if "flask" in content.lower() or "@app.route" in content or "Blueprint" in content:
        endpoints += extract_flask(content, filepath, ctx)
    if "fastapi" in content.lower() or "APIRouter" in content or "@router." in content or "add_api_route" in content:
        endpoints += extract_fastapi(content, filepath, ctx)
        endpoints += extract_add_api_route(content, filepath, ctx)
    if filepath.endswith("urls.py") or "urlpatterns" in content:
        endpoints += extract_django(content, filepath, ctx)

    return endpoints


def walk_repo(repo_dir: str) -> list:
    print("  [Pass 1] Building Python context...")
    ctx = prescan_repo(repo_dir)
    
    all_endpoints  = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            if not filename.endswith(".py"):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, repo_dir)

            content = ctx.contents.get(rel_path)
            if content:
                endpoints = extract_from_file(rel_path, content, ctx)
                all_endpoints.extend(endpoints)

    return all_endpoints


def deduplicate(endpoints: list) -> list:
    seen_line  = set()
    seen_route = set()
    unique     = []
    for ep in endpoints:
        line_key  = (ep.file, ep.line, ep.method)
        route_key = (ep.method, ep.path, str(ep.code)[:100])
        if line_key in seen_line or route_key in seen_route:
            continue
        seen_line.add(line_key)
        seen_route.add(route_key)
        unique.append(ep)
    return unique


def extract(
    repo_url:   str = None,
    local_path: str = None,
    output:     str = "endpoints.json",
) -> list:
    repo_dir = local_path
    if repo_url:
        tmp_dir = tempfile.mkdtemp(prefix="api_sec_")
        repo_dir = tmp_dir
        import git
        git.Repo.clone_from(repo_url, repo_dir, depth=1)

    if not repo_dir or not os.path.exists(repo_dir):
        return []

    print(f"\nScanning Python repository...")
    endpoints = walk_repo(repo_dir)
    endpoints = deduplicate(endpoints)
    
    output_data = [asdict(ep) for ep in endpoints]
    with open(output, "w") as f:
        json.dump(output_data, f, indent=2)

    return output_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help="GitHub URL")
    parser.add_argument("--local", help="Local path")
    parser.add_argument("--output", default="endpoints.json")
    args = parser.parse_args()
    extract(repo_url=args.repo, local_path=args.local, output=args.output)
