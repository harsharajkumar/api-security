"""
API Security Scanner — Streamlit UI (Python Only)
Modern dashboard for Python API vulnerability detection.
"""

import streamlit as st
import requests
import json
import os
import tempfile
import shutil
import re
from datetime import datetime

# ── Page config ───────────────────────────────────────────────────
st.set_page_config(
    page_title="API Security Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="st-"] { font-family: 'Inter', sans-serif; }
    .main { padding-top: 1rem; background-color: #f8fafc; }
    
    /* Improved Repo Card */
    .repo-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 20px;
        transition: transform 0.1s ease;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .repo-card:hover { border-color: #cbd5e1; }
    
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        margin-top: 8px;
    }
    .badge-blue { background: #eff6ff; color: #1d4ed8; border: 1px solid #dbeafe; }
    
    /* Fix Metric Overlap */
    [data-testid="stMetric"] {
        background: white;
        padding: 20px !important;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        min-height: 120px;
    }
    
    /* Step Cards Grid Fix */
    .step-card {
        background: white;
        padding: 2rem 1.5rem;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        text-align: center;
        height: 100%;
        margin-bottom: 1rem;
    }
    .step-icon { font-size: 2.5rem; margin-bottom: 1rem; }
    .step-title { font-weight: 700; color: #1e293b; margin-bottom: 0.75rem; font-size: 1.1rem; }
    .step-desc { font-size: 0.9rem; color: #64748b; line-height: 1.5; }
    
    /* Button Styles */
    .stButton button { 
        border-radius: 8px; 
        font-weight: 600; 
        height: auto;
        padding: 0.5rem 1rem;
    }
    
    /* Container Spacing */
    .block-container { padding-top: 2rem !important; }
    
    /* Sidebar cleanup */
    section[data-testid="stSidebar"] { background-color: #f1f5f9; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────

for key, default in {
    "selected_repo":  None,
    "search_results": [],
    "scan_results":   None,
    "custom_rules":   None,
    "is_scanning":    False,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────

def search_github_repos(query: str, per_page: int = 8) -> list:
    try:
        r = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": f"{query} language:python", "sort": "stars", "order": "desc", "per_page": per_page},
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=8,
        )
        return r.json().get("items", []) if r.status_code == 200 else []
    except Exception: return []

def parse_github_url(url: str) -> dict | None:
    url = url.strip().rstrip("/")
    if "github.com" not in url: return None
    parts = url.replace("https://", "").replace("http://", "").split("/")
    if len(parts) < 3: return None
    owner, repo = parts[1], parts[2]
    try:
        r = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers={"Accept": "application/vnd.github.v3+json"}, timeout=8)
        return r.json() if r.status_code == 200 else None
    except Exception: return None

def parse_uploaded_rules(uploaded_file) -> tuple[list, str]:
    content = uploaded_file.read().decode("utf-8")
    rules = []
    for line in content.splitlines():
        if line.strip():
            try: rules.append(json.loads(line))
            except: pass
    return rules, f"Loaded {len(rules)} rules"

def save_rules_to_temp(rules: list, tmp_dir: str) -> str:
    path = os.path.join(tmp_dir, "custom_rules.jsonl")
    with open(path, "w") as f:
        for rule in rules: f.write(json.dumps(rule) + "\n")
    return path

# ─────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────

def run_full_scan(clone_url, model_dir, rules_file, max_ep, hf_token=""):
    tmp = tempfile.mkdtemp(prefix="api_sec_")
    ep_file    = os.path.join(tmp, "endpoints.json")
    model_file = os.path.join(tmp, "model_results.json")
    rules_out  = os.path.join(tmp, "rules_results.json")

    if hf_token:
        os.environ["HUGGING_FACE_HUB_TOKEN"] = hf_token
        os.environ["HF_TOKEN"] = hf_token

    try:
        from endpoint_extractor import extract
        from rules_checker import run_rules_check

        yield "extract", "Discovery: Scanning repository source code...", None
        endpoints = extract(repo_url=clone_url, output=ep_file)

        if not endpoints:
            yield "error", "No Python API endpoints found in this repository.", None
            return

        total_discovered = len(endpoints)
        if max_ep > 0 and len(endpoints) > max_ep:
            endpoints = endpoints[:max_ep]
            with open(ep_file, "w") as f: json.dump(endpoints, f)

        scanned_count = len(endpoints)
        yield "extract_done", f"Found {total_discovered} endpoints. Scanning {scanned_count}.", total_discovered

        # Model inference using local checkpoint-531 (base model downloaded once & cached)
        model_used = False
        model_error = ""
        yield "model", "AI Analysis: Loading fine-tuned checkpoint (base model cached after first run)...", None
        try:
            from inference import run_inference
            model_results = run_inference(
                endpoints_path=ep_file,
                output_path=model_file,
            )
            model_used = True
        except Exception as me:
            model_error = str(me)
            yield "model_warn", f"AI model unavailable: {model_error[:150]}. Running static analysis only.", None
            model_results = [{**ep, "is_vulnerable": False, "flaws": [], "cwe": [], "severity": "unknown"} for ep in endpoints]

        # Rules check (static analysis — always runs)
        yield "rules", "Validation: Running static analysis and security policy checks...", None
        rules_results = run_rules_check(ep_file, rules_file, rules_out)

        # Merge model + rules results
        rules_index = {(str(r.get("method", "")), str(r.get("path", ""))): r for r in rules_results}
        merged = []
        for m in model_results:
            key = (str(m.get("method", "")), str(m.get("path", "")))
            rr  = rules_index.get(key, {})
            rv  = rr.get("violations", [])
            merged.append({
                **m,
                "rules_violations": rv,
                "is_vulnerable": m.get("is_vulnerable") or len(rv) > 0,
            })

        yield "done", "Scan complete!", {
            "results":          merged,
            "total_discovered": total_discovered,
            "scanned_count":    scanned_count,
            "model_used":       model_used,
            "model_error":      model_error,
        }
    except Exception as e:
        yield "error", f"Scan failed: {e}", None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ─────────────────────────────────────────────────────────────────
# UI — SIDEBAR
# ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("🔒 API Scanner")
    st.divider()
    
    st.subheader("📄 Security Rules")
    uploaded = st.file_uploader("Upload rules (.jsonl)", type=["jsonl"], label_visibility="collapsed")
    if uploaded:
        rules, msg = parse_uploaded_rules(uploaded)
        st.session_state.custom_rules = rules
        st.success(msg)

    st.divider()
    st.subheader("⚙️ Settings")
    audit_mode = st.radio("Scan Mode", ["Quick (20 Endpoints)", "Comprehensive (All)"], index=1)
    max_ep_val = 20 if "Quick" in audit_mode else 0
    hf_token   = ""   # no longer needed — model loads from local checkpoint
    model_dir  = ""

    st.info("Using fine-tuned checkpoint: `checkpoint-531`")
    st.divider()
    st.caption("v2.3 — Local Checkpoint Edition")

# ─────────────────────────────────────────────────────────────────
# UI — MAIN CONTENT
# ─────────────────────────────────────────────────────────────────

st.title("API Security Scanner")
st.markdown("Automated vulnerability assessment for Python API architectures (Flask, FastAPI, Django).")

# Search
query = st.text_input("Repo Search", placeholder="🔍 Enter Python GitHub repo name or URL", label_visibility="collapsed")

if query:
    if "github.com" in query:
        if st.session_state.selected_repo is None or st.session_state.selected_repo.get("html_url") != query:
            with st.spinner("Fetching repo details..."):
                repo_info = parse_github_url(query)
                if repo_info:
                    st.session_state.selected_repo = repo_info
                    st.session_state.search_results = []
    else:
        if st.button("Search Repositories"):
            with st.spinner("Searching GitHub..."):
                st.session_state.search_results = search_github_repos(query)

# Results
if st.session_state.search_results and not st.session_state.selected_repo:
    st.subheader("📦 Search Results")
    for repo in st.session_state.search_results:
        with st.container():
            c_info, c_act = st.columns([4, 1])
            with c_info:
                st.markdown(f'''
                <div class="repo-card">
                    <strong style="font-size:18px; color: #1e293b">{repo.get("full_name")}</strong>
                    <p style="color:#64748b;font-size:14px;margin:8px 0">{repo.get("description") or "No description"}</p>
                    <small style="color:#94a3b8; font-weight: 500">⭐ {repo.get("stargazers_count")} stars</small>
                </div>
                ''', unsafe_allow_html=True)
            with c_act:
                st.write("") # Padding
                st.write("") # Padding
                if st.button("Select", key=f"sel_{repo.get('id')}", use_container_width=True):
                    st.session_state.selected_repo = repo
                    st.rerun()

# Selected
if st.session_state.selected_repo and not st.session_state.scan_results:
    repo = st.session_state.selected_repo
    st.markdown(f'''
    <div class="repo-card" style="border-left: 6px solid #3b82f6; background: #f8fafc">
        <h2 style="margin:0 0 8px 0">{repo.get("full_name")}</h2>
        <p style="color:#64748b;margin-bottom:12px; font-size: 1.1rem">{repo.get("description") or "No description provided."}</p>
        <span class="badge badge-blue">Target: Python</span>
    </div>
    ''', unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1])
    if c1.button("🚀 Start Security Audit", type="primary", use_container_width=True):
        st.session_state.is_scanning = True
        rules_f = save_rules_to_temp(st.session_state.custom_rules, tempfile.mkdtemp()) if st.session_state.custom_rules else "data/api_rules.jsonl"
        
        status_text = st.empty()
        prog = st.progress(0)
        
        for ev, msg, data in run_full_scan(repo["clone_url"], model_dir, rules_f, max_ep_val, hf_token):
            if ev == "model_warn":
                status_text.warning(msg)
            else:
                status_text.info(msg)
            if ev == "extract_done": prog.progress(30)
            elif ev == "model":      prog.progress(50)
            elif ev == "rules":      prog.progress(85)
            elif ev == "done":
                prog.progress(100)
                st.session_state.scan_results = {
                    "repo":             repo["full_name"],
                    "results":          data["results"],
                    "total_discovered": data["total_discovered"],
                    "scanned_count":    data["scanned_count"],
                    "model_used":       data["model_used"],
                    "model_error":      data["model_error"],
                    "timestamp":        datetime.now().isoformat(),
                }
                st.session_state.is_scanning = False
                st.rerun()
            if ev == "error": st.error(msg); break

    if c2.button("Choose Different Repo", use_container_width=True):
        st.session_state.selected_repo = None
        st.rerun()

# Report
if st.session_state.scan_results:
    data = st.session_state.scan_results
    res = data["results"]
    vuln = [r for r in res if r.get("is_vulnerable")]
    
    # Severity-based score
    score = 100
    sev_weights = {"critical": 20, "high": 10, "medium": 5, "low": 2, "unknown": 5}
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    
    for v in res:
        if v.get("is_vulnerable"):
            rvs = v.get("rules_violations", [])
            m_s = v.get("severity", "unknown").lower()
            all_s = [rv.get("severity", "unknown").lower() for rv in rvs]
            if m_s != "unknown": all_s.append(m_s)
            top_s = max(all_s, key=lambda s: sev_order.get(s, 0)) if all_s else "unknown"
            score -= sev_weights.get(top_s, 5)
    score = max(0, score)

    st.header(f"Audit Report: {data['repo']}")

    if data.get("model_used"):
        st.success("AI model analysis completed via HuggingFace Inference API.")
    elif data.get("model_error"):
        st.warning(f"AI model unavailable — results based on static analysis only. ({data['model_error'][:120]})")
    else:
        st.info("Static analysis only — enter a HuggingFace token in the sidebar to enable AI model analysis.")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Discovered", data["total_discovered"])
    m2.metric("Scanned", data.get("scanned_count", len(res)))
    
    score_color = "normal"
    if score < 70: score_color = "inverse"
    m3.metric("Security Score", f"{score}%", delta=None, delta_color=score_color)
    m4.metric("Findings", len(vuln))

    st.write("") # Spacer
    
    c_down, c_new = st.columns([1, 4])
    with c_down:
        st.download_button(
            label="📥 Download JSON",
            data=json.dumps(data, indent=2),
            file_name=f"audit_{data['repo'].replace('/', '_')}.json",
            mime="application/json",
            use_container_width=True
        )
    with c_new:
        if st.button("New Scan", use_container_width=False):
            st.session_state.scan_results = None
            st.session_state.selected_repo = None
            st.rerun()

    st.divider()

    if vuln:
        for v in vuln:
            # Color coding the expander based on top severity
            with st.expander(f"🔴 {v['method']} {v['path']}", expanded=True):
                st.markdown(f"**Source:** `{v.get('file')}` (Line {v.get('line')})")
                t1, t2 = st.tabs(["🔍 Vulnerability Analysis", "🛡️ Secure Version"])
                
                with t1:
                    for rv in v.get("rules_violations", []):
                        st.markdown(f"**{rv.get('attack', 'Security Issue')}:** {', '.join(rv.get('violations', []))}")
                        if rv.get("explanation"): st.info(rv["explanation"])
                    
                    if v.get("vulnerability_description"):
                        st.warning(v["vulnerability_description"])
                    
                    st.code(v.get("code", ""), language="python")
                
                with t2:
                    if v.get("secure_version"):
                        st.success("**Recommended Remediation:**")
                        st.code(v["secure_version"], language="python")
                    else:
                        st.info("No automated remediation available for this logical flaw.")
    else:
        st.success("🎉 No vulnerabilities detected in scanned endpoints.")

# Landing
if not st.session_state.selected_repo and not st.session_state.scan_results:
    st.divider()
    st.subheader("🛠️ Audit Process")
    steps = [
        ("🔍", "Discovery", "Maps Flask, FastAPI, and Django endpoints."),
        ("🤖", "Analysis", "Deep inspection using Code Llama 7B."),
        ("📋", "Policy", "Validated against security rulesets."),
        ("🛡️", "Hardening", "Provides secure remediation code.")
    ]
    cols = st.columns(len(steps))
    for i, (icon, title, desc) in enumerate(steps):
        with cols[i]:
            st.markdown(f'''
            <div class="step-card">
                <div class="step-icon">{icon}</div>
                <div class="step-title">{title}</div>
                <div class="step-desc">{desc}</div>
            </div>
            ''', unsafe_allow_html=True)

    st.markdown('''
    <div class="repo-card" style="margin-top:2rem">
        <h3>📦 Supported Ecosystems</h3>
        <table style="width:100%; border-collapse: collapse; margin-top: 1.5rem">
            <tr style="border-bottom: 2px solid #f1f5f9"><th style="text-align:left; padding:12px">Framework</th><th style="text-align:left; padding:12px">Detection Method</th></tr>
            <tr style="border-bottom: 1px solid #f1f5f9"><td style="padding:12px"><b>Flask</b></td><td style="padding:12px">Route Decorators & Blueprints</td></tr>
            <tr style="border-bottom: 1px solid #f1f5f9"><td style="padding:12px"><b>FastAPI</b></td><td style="padding:12px">APIRouter & Type Hints</td></tr>
            <tr><td style="padding:12px"><b>Django</b></td><td style="padding:12px">URL Patterns & View Tracing</td></tr>
        </table>
    </div>
    ''', unsafe_allow_html=True)




