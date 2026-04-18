"""
Merge LoRA adapter into CodeLlama-7b base and upload the full model to HuggingFace.

Run this ONCE in Google Colab (GPU runtime) or any machine with ~20GB RAM:
    python merge_and_upload.py --token hf_YOUR_TOKEN

After this, the merged model lives at:
    harsharajkumar273/api-security-qlora-merged

The app then calls it via HF Inference API — no local download needed.
"""

import argparse
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
from huggingface_hub import login

ADAPTER_REPO  = "harsharajkumar273/api-security-qlora"
BASE_MODEL    = "codellama/CodeLlama-7b-instruct-hf"
MERGED_REPO   = "harsharajkumar273/api-security-qlora-merged"

def merge_and_push(token: str):
    login(token=token)

    print(f"[1/4] Loading tokenizer from adapter repo...")
    tokenizer = AutoTokenizer.from_pretrained(ADAPTER_REPO, token=token, use_fast=False)

    print(f"[2/4] Loading base model: {BASE_MODEL}")
    print("      (This downloads ~13GB on first run, cached after that)")
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        token=token,
        torch_dtype=torch.float16,
        device_map="auto",
        low_cpu_mem_usage=True,
    )

    print(f"[3/4] Applying LoRA adapter: {ADAPTER_REPO}")
    model = PeftModel.from_pretrained(base, ADAPTER_REPO, token=token)

    print(f"[4/4] Merging LoRA weights into base model...")
    model = model.merge_and_unload()

    print(f"\nUploading merged model to: {MERGED_REPO}")
    model.push_to_hub(MERGED_REPO, token=token, private=False)
    tokenizer.push_to_hub(MERGED_REPO, token=token, private=False)
    print(f"\nDone! Merged model available at: https://huggingface.co/{MERGED_REPO}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True, help="HuggingFace write token")
    args = parser.parse_args()
    merge_and_push(args.token)
