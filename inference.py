"""
Inference Script
Loads the fine-tuned Code Llama model and runs each
extracted endpoint through it to detect vulnerabilities.

Usage:
    python inference.py --endpoints endpoints.json --model_dir ./finetuned_model/final
"""

import json
import argparse
import re


# ─────────────────────────────────────────────────────────────────
# 1. LOAD MODEL
# ─────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a security-focused code reviewer specializing in API vulnerability "
    "detection and remediation. Analyze the provided code, identify security flaws, "
    "explain the vulnerabilities, and provide a secure version."
)


def load_model(model_dir: str, base_model: str = "codellama/CodeLlama-7b-instruct-hf"):
    """Load fine-tuned LoRA adapter + tokenizer."""
    import os
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    # Read base model from adapter_config if present
    adapter_cfg_path = os.path.join(model_dir, "adapter_config.json")
    if os.path.exists(adapter_cfg_path):
        with open(adapter_cfg_path) as f:
            adapter_cfg = json.load(f)
        base_model = adapter_cfg.get("base_model_name_or_path", base_model)

    print(f"[1/3] Loading tokenizer from {model_dir}...")
    tokenizer = AutoTokenizer.from_pretrained(model_dir, use_fast=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token    = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    print(f"[2/3] Loading base model: {base_model}...")

    # Detect device
    if torch.cuda.is_available():
        device = "cuda"
        print(f"  Using GPU: {torch.cuda.get_device_name(0)}")
    elif torch.backends.mps.is_available():
        device = "mps"
        print(f"  Using MPS (Apple Silicon)")
    else:
        device = "cpu"
        print(f"  Using CPU (slow)")

    torch_dtype = torch.float16 if device != "cpu" else torch.float32

    base = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch_dtype,
        device_map="auto",
        low_cpu_mem_usage=True,
    )

    print(f"[3/3] Applying LoRA adapter from {model_dir}...")
    model = PeftModel.from_pretrained(base, model_dir)
    model.eval()

    print("  Model loaded!")
    return model, tokenizer, device


# ─────────────────────────────────────────────────────────────────
# 2. PROMPT BUILDER
# ─────────────────────────────────────────────────────────────────

def build_prompt(endpoint: dict) -> str:
    """Build CodeLlama [INST] instruct prompt matching fine-tune format."""
    lang      = endpoint.get("language", "Unknown")
    framework = endpoint.get("framework", "Unknown")
    method    = endpoint.get("method", "GET")
    path      = endpoint.get("path", "/api/unknown")
    code      = endpoint.get("code", "")

    instruction = (
        f"Analyze the following {lang} ({framework}) API endpoint "
        f"for security vulnerabilities.\n\n"
        f"HTTP Method : {method}\n"
        f"Endpoint    : {path}\n\n"
        f"```{lang.lower()}\n{code}\n```"
    )

    return (
        f"<s>[INST] <<SYS>>\n{SYSTEM_PROMPT}\n<</SYS>>\n\n"
        f"{instruction} [/INST]\n"
    )


# ─────────────────────────────────────────────────────────────────
# 3. RESPONSE PARSER
#    Extracts structured fields from raw model output
# ─────────────────────────────────────────────────────────────────

def parse_response(raw: str) -> dict:
    """
    Parse model output that follows the fine-tune response format:

        ## Vulnerability Analysis
        **Severity**       : HIGH
        **Flaw(s)**        : SQL Injection, ...
        **CWE**            : CWE-89, ...

        **Description**
        ...

        ## Secure Version
        ```language
        ...
        ```
    """

    def extract_inline(label: str, text: str) -> str:
        """Extract value after a bold label on the same line: **Label** : value"""
        m = re.search(
            r"\*\*" + re.escape(label) + r"\*\*\s*:?\s*(.+?)(?:\n|$)",
            text, re.IGNORECASE
        )
        return m.group(1).strip().strip("*").strip() if m else ""

    # ── Severity ─────────────────────────────────────────────────────
    severity_raw = extract_inline("Severity", raw)
    severity     = severity_raw.lower() if severity_raw else "unknown"

    # ── Flaw(s) ──────────────────────────────────────────────────────
    flaws_raw = extract_inline("Flaw(s)", raw) or extract_inline("Flaw", raw)
    flaws = [f.strip().strip("*") for f in re.split(r"[,;]", flaws_raw) if f.strip()] if flaws_raw else []

    # ── CWE ──────────────────────────────────────────────────────────
    cwe_raw = extract_inline("CWE", raw)
    cwes    = re.findall(r"CWE-\d+", cwe_raw.upper()) if cwe_raw else []

    # ── Description (multi-line block after **Description**) ─────────
    desc_match = re.search(
        r"\*\*Description\*\*\s*\n(.*?)(?:\n##|\Z)",
        raw, re.DOTALL | re.IGNORECASE
    )
    description = desc_match.group(1).strip() if desc_match else ""

    # ── Secure Version (code block after ## Secure Version) ──────────
    secure_match = re.search(
        r"##\s*Secure Version.*?```[a-z]*\n(.*?)```",
        raw, re.DOTALL | re.IGNORECASE
    )
    secure_version = secure_match.group(1).strip() if secure_match else ""

    # ── Determine vulnerability ───────────────────────────────────────
    is_vulnerable = severity not in ("none", "n/a", "unknown", "") or bool(flaws)

    return {
        "is_vulnerable":             is_vulnerable,
        "flaws":                     flaws,
        "cwe":                       cwes,
        "severity":                  severity,
        "vulnerability_description": description,
        "secure_version":            secure_version,
        "raw_response":              raw,
    }


# ─────────────────────────────────────────────────────────────────
# 4. RUN INFERENCE
# ─────────────────────────────────────────────────────────────────

def analyze_endpoint(
    endpoint: dict,
    model,
    tokenizer,
    device: str,
    max_new_tokens: int = 400,
) -> dict:
    """Run model inference on a single endpoint."""
    prompt = build_prompt(endpoint)

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=1024,
    ).to(device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            temperature=0.1,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    # Decode only new tokens (not the prompt)
    new_tokens = outputs[0][inputs["input_ids"].shape[1]:]
    raw        = tokenizer.decode(new_tokens, skip_special_tokens=True)

    result = parse_response(raw)
    result.update({
        "file":      endpoint.get("file"),
        "line":      endpoint.get("line"),
        "method":    endpoint.get("method"),
        "path":      endpoint.get("path"),
        "language":  endpoint.get("language"),
        "framework": endpoint.get("framework"),
        "code":      endpoint.get("code"),
    })

    return result


def run_inference(
    endpoints_path: str,
    model_dir:      str,
    output_path:    str = "model_results.json",
    base_model:     str = "codellama/CodeLlama-7b-instruct-hf",
) -> list:
    """Run inference on all extracted endpoints."""

    # Load endpoints
    with open(endpoints_path) as f:
        endpoints = json.load(f)
    print(f"\nLoaded {len(endpoints)} endpoints from {endpoints_path}")

    # Load model
    model, tokenizer, device = load_model(model_dir, base_model)

    # Run inference
    print(f"\nAnalyzing endpoints...")
    results = []

    for i, endpoint in enumerate(endpoints):
        print(f"  [{i+1}/{len(endpoints)}] {endpoint.get('method')} {endpoint.get('path')}  ({endpoint.get('framework')})")

        try:
            result = analyze_endpoint(endpoint, model, tokenizer, device)
            results.append(result)

            status = "VULNERABLE" if result["is_vulnerable"] else "CLEAN"
            severity = result.get("severity", "")
            flaws    = ", ".join(result.get("flaws", []))
            print(f"          → {status}  {severity}  {flaws}")

        except Exception as e:
            print(f"          → ERROR: {e}")
            results.append({
                "file":     endpoint.get("file"),
                "line":     endpoint.get("line"),
                "method":   endpoint.get("method"),
                "path":     endpoint.get("path"),
                "language": endpoint.get("language"),
                "framework":endpoint.get("framework"),
                "code":     endpoint.get("code"),
                "error":    str(e),
                "is_vulnerable": False,
            })

    # Save results
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    vuln_count = sum(1 for r in results if r.get("is_vulnerable"))
    print(f"\n[OK] Inference complete!")
    print(f"  Total endpoints : {len(results)}")
    print(f"  Vulnerable      : {vuln_count}")
    print(f"  Clean           : {len(results) - vuln_count}")
    print(f"  Results saved   : {output_path}")

    return results


# ─────────────────────────────────────────────────────────────────
# 5. MAIN
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run fine-tuned model inference on extracted endpoints"
    )
    parser.add_argument(
        "--endpoints",  default="endpoints.json",
        help="Endpoints JSON from endpoint_extractor.py"
    )
    parser.add_argument(
        "--model_dir",  required=True,
        help="Path to fine-tuned model directory"
    )
    parser.add_argument(
        "--output",     default="model_results.json",
        help="Output file for inference results"
    )
    parser.add_argument(
        "--base_model", default="codellama/CodeLlama-7b-instruct-hf",
        help="Base model name (used for tokenizer fallback)"
    )
    args = parser.parse_args()

    print("=" * 55)
    print("  API Security Inference")
    print("=" * 55)

    run_inference(
        endpoints_path = args.endpoints,
        model_dir      = args.model_dir,
        output_path    = args.output,
        base_model     = args.base_model,
    )

    print(f"\nNext step:")
    print(f"  python rules_checker.py --endpoints {args.endpoints} --results {args.output}")


if __name__ == "__main__":
    main()
