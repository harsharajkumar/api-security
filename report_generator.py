"""
Report Generator
Merges model inference results + rules checker results
into a final HTML vulnerability report.

Usage:
    python report_generator.py \
        --model_results model_results.json \
        --rules_results rules_results.json \
        --output report.html
"""

import json
import argparse
from datetime import datetime
from collections import Counter


# ─────────────────────────────────────────────────────────────────
# 1. MERGE RESULTS
# ─────────────────────────────────────────────────────────────────

def merge_results(model_results: list, rules_results: list) -> list:
    """
    Merge model inference results with rules checker results
    by matching on file + method + path.
    """
    # Index rules results by (method, path)
    rules_index = {}
    for r in rules_results:
        key = (r.get("method"), r.get("path"))
        rules_index[key] = r

    merged = []
    for m in model_results:
        key        = (m.get("method"), m.get("path"))
        rules_data = rules_index.get(key, {})

        merged.append({
            "file":      m.get("file", ""),
            "line":      m.get("line", 0),
            "method":    m.get("method", "GET"),
            "path":      m.get("path", "/"),
            "language":  m.get("language", ""),
            "framework": m.get("framework", ""),
            "code":      m.get("code", ""),

            # From model
            "model_vulnerable":   m.get("is_vulnerable", False),
            "model_flaws":        m.get("flaws", []),
            "model_cwe":          m.get("cwe", []),
            "model_severity":     m.get("severity", "unknown"),
            "model_description":  m.get("vulnerability_description", ""),
            "model_secure":       m.get("secure_version", ""),

            # From rules
            "rules_violations":   rules_data.get("violations", []),
            "rules_matched":      rules_data.get("rules_matched", 0),

            # Combined
            "is_vulnerable": (
                m.get("is_vulnerable", False) or
                len(rules_data.get("violations", [])) > 0
            ),
        })

    return merged


# ─────────────────────────────────────────────────────────────────
# 2. SEVERITY SCORING
# ─────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

def overall_severity(item: dict) -> str:
    """Determine highest severity from model + rules results."""
    severities = []

    if item.get("model_severity"):
        severities.append(item["model_severity"])

    for v in item.get("rules_violations", []):
        if v.get("severity"):
            severities.append(v["severity"])

    if not severities:
        return "unknown"

    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


# ─────────────────────────────────────────────────────────────────
# 3. HTML REPORT BUILDER
# ─────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#65a30d",
    "unknown":  "#6b7280",
    "clean":    "#16a34a",
}

SEVERITY_BADGE = {
    "critical": "🔴 Critical",
    "high":     "🟠 High",
    "medium":   "🟡 Medium",
    "low":      "🟢 Low",
    "unknown":  "⚪ Unknown",
}


def severity_badge_html(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    label = SEVERITY_BADGE.get(severity, severity.title())
    return (
        f'<span style="background:{color};color:white;'
        f'padding:2px 10px;border-radius:12px;font-size:12px;'
        f'font-weight:bold">{label}</span>'
    )


def method_badge_html(method: str) -> str:
    colors = {
        "GET":    "#3b82f6", "POST":   "#10b981",
        "PUT":    "#f59e0b", "DELETE": "#ef4444",
        "PATCH":  "#8b5cf6", "OPTIONS":"#6b7280",
    }
    color = colors.get(method.upper(), "#6b7280")
    return (
        f'<span style="background:{color};color:white;'
        f'padding:2px 8px;border-radius:4px;font-size:12px;'
        f'font-weight:bold;font-family:monospace">{method}</span>'
    )


def build_html_report(merged: list, repo_name: str = "Unknown Repo") -> str:
    """Build complete HTML vulnerability report."""
    now           = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    vulnerable    = [m for m in merged if m["is_vulnerable"]]
    clean         = [m for m in merged if not m["is_vulnerable"]]

    # Severity breakdown
    sev_counts = Counter()
    for item in vulnerable:
        sev = overall_severity(item)
        sev_counts[sev] += 1

    # All unique flaws
    all_flaws = Counter()
    for item in vulnerable:
        for f in item.get("model_flaws", []):
            all_flaws[f] += 1

    # ── Summary cards HTML ────────────────────────────────────────
    def summary_card(label, value, color):
        return f"""
        <div style="background:white;border-radius:12px;padding:20px 28px;
                    box-shadow:0 1px 4px rgba(0,0,0,0.08);text-align:center;
                    border-top:4px solid {color}">
            <div style="font-size:36px;font-weight:bold;color:{color}">{value}</div>
            <div style="color:#6b7280;font-size:14px;margin-top:4px">{label}</div>
        </div>"""

    summary_html = f"""
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:32px">
        {summary_card("Total Endpoints",  len(merged),              "#3b82f6")}
        {summary_card("Vulnerable",        len(vulnerable),          "#ef4444")}
        {summary_card("Clean",             len(clean),               "#10b981")}
        {summary_card("Critical",          sev_counts.get('critical',0), "#dc2626")}
        {summary_card("High",              sev_counts.get('high',0),    "#ea580c")}
    </div>"""

    # ── Vulnerability cards HTML ──────────────────────────────────
    vuln_cards_html = ""
    for item in sorted(
        vulnerable,
        key=lambda x: SEVERITY_ORDER.get(overall_severity(x), 0),
        reverse=True
    ):
        sev         = overall_severity(item)
        color       = SEVERITY_COLORS.get(sev, "#6b7280")
        flaws_str   = ", ".join(item.get("model_flaws", [])) or "spec violation"
        cwes_str    = ", ".join(item.get("model_cwe", [])) or ""
        description = item.get("model_description", "")
        secure      = item.get("model_secure", "")
        code        = item.get("code", "")
        rules_viols = item.get("rules_violations", [])

        # Rules violations HTML
        rules_html = ""
        if rules_viols:
            rules_html = "<div style='margin-top:12px'><strong>📋 Rules Violations:</strong><ul style='margin:8px 0;padding-left:20px'>"
            for v in rules_viols:
                for viol in v.get("violations", []):
                    rules_html += f"<li style='color:#92400e;font-size:13px'>{viol}</li>"
            rules_html += "</ul></div>"

        # Secure version HTML
        secure_html = ""
        if secure:
            secure_html = f"""
            <div style="margin-top:16px">
                <strong style="color:#16a34a">✅ Secure Version:</strong>
                <pre style="background:#f0fdf4;border:1px solid #bbf7d0;
                            border-radius:8px;padding:12px;margin-top:8px;
                            font-size:12px;overflow-x:auto;white-space:pre-wrap">{secure}</pre>
            </div>"""

        vuln_cards_html += f"""
        <div style="background:white;border-radius:12px;margin-bottom:20px;
                    box-shadow:0 1px 4px rgba(0,0,0,0.08);
                    border-left:5px solid {color};overflow:hidden">
            <div style="padding:16px 20px;border-bottom:1px solid #f3f4f6;
                        display:flex;align-items:center;gap:12px;flex-wrap:wrap">
                {method_badge_html(item['method'])}
                <code style="font-size:15px;font-weight:600;color:#1f2937">
                    {item['path']}
                </code>
                {severity_badge_html(sev)}
                <span style="color:#6b7280;font-size:12px;margin-left:auto">
                    {item.get('file','')}:{item.get('line','')}
                    ({item.get('framework','')})
                </span>
            </div>
            <div style="padding:16px 20px">
                <div style="margin-bottom:8px">
                    <span style="font-weight:600;color:#dc2626">⚠️ Flaws: </span>
                    <code style="background:#fef2f2;padding:2px 8px;border-radius:4px;
                                 font-size:13px;color:#dc2626">{flaws_str}</code>
                    {"&nbsp;&nbsp;<span style='color:#6b7280;font-size:12px'>" + cwes_str + "</span>" if cwes_str else ""}
                </div>
                {f'<p style="color:#374151;font-size:14px;margin:8px 0">{description}</p>' if description else ""}
                <details>
                    <summary style="cursor:pointer;color:#6b7280;font-size:13px;
                                    margin-top:8px">View Code</summary>
                    <pre style="background:#1e1e1e;color:#d4d4d4;border-radius:8px;
                                padding:12px;margin-top:8px;font-size:12px;
                                overflow-x:auto;white-space:pre-wrap">{code}</pre>
                </details>
                {rules_html}
                {secure_html}
            </div>
        </div>"""

    # ── Clean endpoints summary ───────────────────────────────────
    clean_html = ""
    if clean:
        clean_rows = "".join(
            f"<tr><td style='padding:8px 12px'>{method_badge_html(c['method'])}</td>"
            f"<td style='padding:8px 12px;font-family:monospace;font-size:13px'>{c['path']}</td>"
            f"<td style='padding:8px 12px;color:#6b7280;font-size:12px'>{c.get('file','')}</td>"
            f"<td style='padding:8px 12px;color:#6b7280;font-size:12px'>{c.get('framework','')}</td></tr>"
            for c in clean
        )
        clean_html = f"""
        <div style="background:white;border-radius:12px;margin-top:32px;
                    box-shadow:0 1px 4px rgba(0,0,0,0.08);overflow:hidden">
            <div style="padding:16px 20px;border-bottom:1px solid #f3f4f6;
                        display:flex;align-items:center;gap:8px">
                <span style="font-size:18px">✅</span>
                <h2 style="margin:0;font-size:18px;color:#16a34a">
                    Clean Endpoints ({len(clean)})
                </h2>
            </div>
            <div style="overflow-x:auto">
                <table style="width:100%;border-collapse:collapse">
                    <thead>
                        <tr style="background:#f9fafb;font-size:12px;color:#6b7280;text-transform:uppercase">
                            <th style="padding:8px 12px;text-align:left">Method</th>
                            <th style="padding:8px 12px;text-align:left">Path</th>
                            <th style="padding:8px 12px;text-align:left">File</th>
                            <th style="padding:8px 12px;text-align:left">Framework</th>
                        </tr>
                    </thead>
                    <tbody>{clean_rows}</tbody>
                </table>
            </div>
        </div>"""

    # ── Full HTML ─────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Report — {repo_name}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f3f4f6;
            color: #111827;
            padding: 32px 20px;
        }}
        details summary {{ list-style: none; }}
        details summary::-webkit-details-marker {{ display: none; }}
    </style>
</head>
<body>
<div style="max-width:960px;margin:0 auto">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);
                border-radius:16px;padding:32px;margin-bottom:32px;color:white">
        <h1 style="font-size:28px;margin-bottom:8px">🔒 API Security Report</h1>
        <div style="opacity:0.8;font-size:14px">
            Repository: <strong>{repo_name}</strong> &nbsp;|&nbsp;
            Generated: {now}
        </div>
    </div>

    <!-- Summary Cards -->
    {summary_html}

    <!-- Vulnerable Endpoints -->
    <div style="margin-bottom:24px">
        <h2 style="font-size:20px;color:#dc2626;margin-bottom:16px">
            ⚠️ Vulnerable Endpoints ({len(vulnerable)})
        </h2>
        {vuln_cards_html if vuln_cards_html else
         '<p style="color:#6b7280;padding:20px;background:white;border-radius:12px">No vulnerabilities found!</p>'}
    </div>

    <!-- Clean Endpoints -->
    {clean_html}

    <!-- Footer -->
    <div style="text-align:center;color:#9ca3af;font-size:12px;margin-top:32px;padding:16px">
        Generated by API Security Scanner &nbsp;|&nbsp;
        Powered by Code Llama Fine-tuned Model + Rules Engine
    </div>

</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────
# 4. MAIN
# ─────────────────────────────────────────────────────────────────

def generate_report(
    model_results_path: str,
    rules_results_path: str,
    output_path:        str = "report.html",
    repo_name:          str = "Unknown Repo",
):
    print(f"\n[1/3] Loading results...")

    with open(model_results_path) as f:
        model_results = json.load(f)
    print(f"  Model results : {len(model_results)}")

    with open(rules_results_path) as f:
        rules_results = json.load(f)
    print(f"  Rules results : {len(rules_results)}")

    print(f"\n[2/3] Merging and building report...")
    merged = merge_results(model_results, rules_results)

    html = build_html_report(merged, repo_name)

    print(f"\n[3/3] Saving report → {output_path}")
    with open(output_path, "w") as f:
        f.write(html)

    vuln_count = sum(1 for m in merged if m["is_vulnerable"])
    print(f"\n[OK] Report complete!")
    print(f"  Total endpoints : {len(merged)}")
    print(f"  Vulnerable      : {vuln_count}")
    print(f"  Clean           : {len(merged) - vuln_count}")
    print(f"  Open {output_path} in your browser to view the report")


def main():
    parser = argparse.ArgumentParser(
        description="Generate HTML vulnerability report"
    )
    parser.add_argument("--model_results", default="model_results.json")
    parser.add_argument("--rules_results", default="rules_results.json")
    parser.add_argument("--output",        default="report.html")
    parser.add_argument("--repo_name",     default="Unknown Repo")
    args = parser.parse_args()

    print("=" * 55)
    print("  API Security Report Generator")
    print("=" * 55)

    generate_report(
        model_results_path = args.model_results,
        rules_results_path = args.rules_results,
        output_path        = args.output,
        repo_name          = args.repo_name,
    )


if __name__ == "__main__":
    main()
