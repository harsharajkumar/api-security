# 🔒 API Security Scanner

An end-to-end API vulnerability detection system that combines structural code analysis, a fine-tuned **Code Llama 7B** model, and a rule-based validation engine. It is designed to scan GitHub repositories and detect both code-level logic flaws and contract-level spec violations.

---

## 🏗️ Architecture: The 4-Stage Audit

Our approach separates vulnerability detection into four distinct, interoperable stages:

1.  **Structural Discovery (`endpoint_extractor.py`)**: Uses a robust multi-mode parser (Brace-matching for C-style languages, Indentation-tracking for Python/Ruby) to map API endpoints across 10+ languages and frameworks.
2.  **AI Inspection (`inference.py`)**: Leverages a fine-tuned Code Llama model (QLoRA) to perform deep-code analysis. It detects vulnerabilities like SQLi, IDOR, and Mass Assignment, providing both an analysis and a recommended secure implementation.
3.  **Policy Validation (`rules_checker.py`)**: A rule-based engine that validates extracted code against custom security policies or OpenAPI specs using advanced fuzzy path matching (`/api/users/{id}` → `api/users/:param`).
4.  **Report Generation (`report_generator.py`)**: Merges AI and rules results, computes a security score by severity weight, and produces an interactive HTML report.

---

## 🗺️ System Design

```mermaid
flowchart TD
    subgraph INPUT["Input Sources"]
        A1[GitHub URL]
        A2[Local Path]
    end

    subgraph ENTRY["Entry Points"]
        B1[app.py\nStreamlit Dashboard]
        B2[pipeline.py\nCLI Orchestrator]
    end

    subgraph STAGE1["Stage 1 — Endpoint Extraction\nendpoint_extractor.py"]
        C1[Git Clone / Local Walk]
        C2[Pre-scan Phase\nCollect router & blueprint prefixes]
        C3[Flask Extractor\n@app.route / @bp.route]
        C4[FastAPI Extractor\n@router.get/post + multi-line decorators\nadd_api_route support]
        C5[Django Extractor\nurlpatterns / router.register]
        C6[Deduplicate\nby file+line+method]
        C7[(endpoints.json)]
    end

    subgraph STAGE2["Stage 2 — AI Inference\ninference.py"]
        D1{Model Source}
        D2[Local Checkpoint\nnotebooks/model_folder/checkpoint-531]
        D3[HuggingFace Hub\nharsharajkumar273/api-security-qlora]
        D4[Base Model\nCodeLlama-7b-instruct-hf]
        D5[LoRA Adapter\nQLoRA 4-bit NF4]
        D6[Build Prompt\nINST format with\nmethod + path + code]
        D7[Model Generate\nmax 400 new tokens]
        D8[Parse Response\nSeverity / Flaws / CWE\nDescription / Secure Version]
        D9[(model_results.json)]
    end

    subgraph STAGE3["Stage 3 — Rules Checker\nrules_checker.py"]
        E1[Load api_rules.jsonl\nFuzzy path matching]
        E2[Static Pattern Matching\nSQL Injection · Command Injection\nPath Traversal · SSRF · IDOR\nInsecure JWT · Hardcoded Secret\nInsecure Deserialization · XSS]
        E3[Config File Scanner\nsettings.py / config.py\nHardcoded secrets only]
        E4[Custom Rule Engine\nMissing Auth · Missing Security Params]
        E5[(rules_results.json)]
    end

    subgraph STAGE4["Stage 4 — Report Generator\nreport_generator.py"]
        F1[Merge Model + Rules Results]
        F2[Compute Security Score\nby severity weights]
        F3[(report.html)]
    end

    subgraph FINETUNE["Fine-Tuning Pipeline\nfinetune/"]
        G1[(api_vulnerability_dataset_10k.json\n10,000 samples · 19 vuln types)]
        G2[data.py\nDataset Prep & Normalization]
        G3[finetune.py\nQLoRA Training\nrank=16 · alpha=32\ntarget: q/k/v/o_proj]
        G4[API_Vuln_QLoRA_Colab_Fixed.ipynb\nGoogle Colab T4 GPU]
        G5[merge_and_upload.py\nMerge LoRA → Base\nUpload to HF Hub]
        G6[(harsharajkumar273/\napi-security-qlora\nHuggingFace Hub)]
    end

    A1 & A2 --> B1 & B2
    B1 & B2 --> C1
    C1 --> C2
    C2 --> C3 & C4 & C5
    C3 & C4 & C5 --> C6 --> C7

    C7 --> D6
    D1 -->|exists locally| D2
    D1 -->|fallback| D3
    D2 & D3 --> D5
    D4 --> D5
    D5 --> D6 --> D7 --> D8 --> D9

    C7 --> E1 & E2 & E3 & E4
    E1 & E2 & E3 & E4 --> E5

    D9 & E5 --> F1 --> F2 --> F3

    G1 --> G2 --> G3
    G4 --> G3 --> G5 --> G6
    G6 -.->|adapter loaded at runtime| D3
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install streamlit gitpython requests transformers peft torch pyyaml
```

### 2. Launch the Dashboard
```bash
streamlit run app.py
```

### 3. CLI Alternative
For headless environments or CI/CD pipelines:
```bash
python pipeline.py --repo https://github.com/user/api-repo --model_dir ./finetuned_model/final
```

---

## 🖥️ Dashboard Features

*   **Repository Discovery**: Search GitHub directly from the UI or paste a URL to initiate an audit.
*   **Audit Mode Selector**:
    *   **Quick**: Scans the first 20 endpoints.
    *   **Standard**: Scans up to 50 endpoints.
    *   **Comprehensive**: Audits every detected endpoint in the codebase.
*   **Custom Rules Engine**: Upload `.jsonl` rules, `.yaml` OpenAPI specs, or even `.md` documentation to use as security test cases.
*   **Interactive Reports**:
    *   **Security Score**: Real-time grading based on vulnerability count and severity.
    *   **Remediation Tabs**: View vulnerable code side-by-side with model-generated secure versions.
    *   **Export**: Download full audit results as structured JSON reports.

---

## 🔍 Supported Ecosystems

| Language | Supported Frameworks |
| :--- | :--- |
| **Python** | Flask, FastAPI, Django |
| **JavaScript/TS** | Express.js, NestJS |
| **Java** | Spring Boot |
| **PHP** | Laravel |
| **Go** | Gin, net/http |
| **Ruby** | Ruby on Rails |
| **C#** | ASP.NET Core |

---

## 📊 Dataset Insights

The model was fine-tuned on a high-quality, diverse dataset of **10,000 API-specific vulnerability samples**. This dataset provides the foundation for the scanner's ability to recognize complex security patterns across multiple ecosystems.

### 🌐 Language & Framework Distribution
The training data covers a wide range of modern back-end technologies, ensuring robust cross-language performance:

*   **Python (46%)**: Dominated by Flask and Django samples.
*   **JavaScript (25%)**: Primarily focused on Express.js middleware and handlers.
*   **Java (15%)**: Comprehensive coverage of Spring Boot REST controllers.
*   **PHP, Go, Ruby, C# (14%)**: Targeted samples for Laravel, Gin, Rails, and ASP.NET.

### 🛡️ Vulnerability Landscape
Our dataset specifically targets the most critical API security risks (OWASP API Top 10):

| Top Vulnerability Types | Count | Common CWEs |
| :--- | :--- | :--- |
| **SQL Injection** | 2,425 | CWE-89 |
| **Mass Assignment** | 1,307 | CWE-915 |
| **Path Traversal** | 943 | CWE-22 |
| **IDOR** | 860 | CWE-639 |
| **Broken Authorization** | 792 | CWE-285 |
| **Command Injection** | 600 | CWE-78 |

### 📈 Severity Breakdown
*   **Critical (43%)**: Direct RCE, SQLi, or unauthorized admin access.
*   **High (41%)**: Data leaks, IDOR, and severe authorization bypass.
*   **Medium/None (16%)**: XSS, input validation warnings, and "Clean" baseline samples to reduce false positives.

---

## 🧠 Fine-Tuning & Data

*   **Model**: `CodeLlama-7b-instruct-hf`
*   **Method**: QLoRA (4-bit NF4 quantization) for efficient training on T4/16GB VRAM.
*   **Dataset**: ~10,000 samples (synthetic + augmented) covering 19 vulnerability types (SQLi, OS Command Injection, Path Traversal, etc.).
*   **Resilient Parsing**: The inference engine is equipped with a high-resilience parser that handles varying LLM output formats and structured JSON blocks.

---

## 📁 Project Structure

```text
api-security/
├── app.py                    # Streamlit dashboard (entry point)
├── pipeline.py               # CLI orchestrator (entry point)
├── endpoint_extractor.py     # Multi-language endpoint mapper
├── inference.py              # Model inference engine
├── rules_checker.py          # Fuzzy-matching policy validator
├── report_generator.py       # HTML/JSON report builder
├── data/
│   ├── api_rules.jsonl           # Security rules dataset
│   └── api_vulnerability_dataset_10k.json  # Training dataset
├── finetune/
│   ├── finetune.py           # QLoRA training script
│   ├── data.py               # Dataset preparation & normalization
│   └── extract_rules.py      # Rules extraction from OpenAPI/Markdown
├── notebooks/
│   └── API_Vuln_QLoRA_Colab_Fixed.ipynb  # Training notebook
├── Dockerfile
├── docker-compose.yml
├── requirements.txt          # App dependencies
└── requirements-ml.txt       # ML/training dependencies
```

---

## 👥 Team & Credits

**CS6380 — API Security Project**
Developed by: Siddhanth Nilesh Jagtap · Tanuj Kenchannavar · Harsha Raj Kumar

## QloRA_Model Document
https://docs.google.com/document/d/1Gr8nihhJKUCkgGdu-fUO2g-c9134bzZ7oMeGSMI-oqw/edit?usp=sharing
