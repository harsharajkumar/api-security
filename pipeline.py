"""
Main Pipeline (Python Only)
Orchestrates endpoint extraction, model inference, and rule checking.
"""

import os
import json
import argparse

from endpoint_extractor import extract
from inference          import run_inference, HF_ADAPTER_REPO
from rules_checker      import run_rules_check
from report_generator   import generate_report

def run_pipeline(
    repo_url:   str  = None,
    local_path: str  = None,
    model_dir:  str  = HF_ADAPTER_REPO,
    rules_file: str  = "data/api_rules.jsonl",
    output_dir: str  = "./output",
    repo_name:  str  = "Unknown Repo",
):
    os.makedirs(output_dir, exist_ok=True)

    endpoints_file    = f"{output_dir}/endpoints.json"
    model_results_file= f"{output_dir}/model_results.json"
    rules_results_file= f"{output_dir}/rules_results.json"
    report_file       = f"{output_dir}/report.html"

    print("\n[STEP 1/4] Extracting Python API endpoints...")
    endpoints = extract(repo_url=repo_url, local_path=local_path, output=endpoints_file)

    if not endpoints:
        print("[!] No Python endpoints found.")
        return

    print(f"\n[STEP 2/4] Running model inference on {len(endpoints)} endpoints...")
    run_inference(endpoints_path=endpoints_file, model_dir=model_dir, output_path=model_results_file)

    print("\n[STEP 3/4] Running rules checker...")
    run_rules_check(endpoints_path=endpoints_file, rules_path=rules_file, output_path=rules_results_file)

    print("\n[STEP 4/4] Generating report...")
    generate_report(
        model_results_path = model_results_file,
        rules_results_path = rules_results_file,
        output_path        = report_file,
        repo_name          = repo_name,
    )

    print(f"\nPipeline Complete! Report: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help="GitHub URL")
    parser.add_argument("--local", help="Local path")
    parser.add_argument("--model_dir", default=HF_ADAPTER_REPO)
    parser.add_argument("--rules", default="data/api_rules.jsonl")
    parser.add_argument("--output_dir", default="./output")
    args = parser.parse_args()

    name = args.repo.split("/")[-1] if args.repo else os.path.basename(args.local)
    run_pipeline(repo_url=args.repo, local_path=args.local, model_dir=args.model_dir, rules_file=args.rules, output_dir=args.output_dir, repo_name=name)
