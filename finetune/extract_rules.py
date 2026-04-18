# import yaml
# import os

# RULES = []

# def extract_rules_from_file(file_path):
#     with open(file_path, "r", encoding="utf-8") as f:
#         spec = yaml.safe_load(f)

#     paths = spec.get("paths", {})

#     for endpoint, methods in paths.items():
#         for method, details in methods.items():

#             if not isinstance(details, dict):
#                 continue

#             # Authentication rules
#             if "security" in details:
#                 RULES.append({
#                     "type": "auth_required",
#                     "endpoint": endpoint,
#                     "method": method
#                 })

#             # Parameter rules
#             params = details.get("parameters", [])

#             for p in params:
#                 rule = {
#                     "endpoint": endpoint,
#                     "method": method,
#                     "parameter": p.get("name"),
#                     "required": p.get("required", False),
#                     "type": p.get("schema", {}).get("type"),
#                     "enum": p.get("schema", {}).get("enum"),
#                     "minimum": p.get("schema", {}).get("minimum"),
#                     "maximum": p.get("schema", {}).get("maximum")
#                 }

#                 RULES.append(rule)


# def main():

#     folder = "./"   # directory with yaml files

#     for file in os.listdir(folder):
#         if file.endswith(".yaml") or file.endswith(".yml"):
#             extract_rules_from_file(os.path.join(folder, file))

#     for r in RULES:
#         print(r)


# if __name__ == "__main__":
#     main()

# import os
# import yaml
# import json

# folder = "./"   # folder where your files are


# def extract_rules_from_openapi(data, filename):

#     print(f"\n--- RULES FROM {filename} ---")

#     paths = data.get("paths", {})

#     for path, methods in paths.items():

#         if not isinstance(methods, dict):
#             continue

#         for method, details in methods.items():

#             if not isinstance(details, dict):
#                 continue

#             endpoint = f"{method.upper()} {path}"

#             # SECURITY
#             security = details.get("security")
#             if security:
#                 print(f"[AUTH RULE] {endpoint} requires authentication")

#             # PARAMETERS
#             parameters = details.get("parameters", [])

#             for param in parameters:

#                 name = param.get("name")
#                 required = param.get("required", False)
#                 schema = param.get("schema", {})

#                 if required:
#                     print(f"[RULE] {endpoint} requires parameter '{name}'")

#                 if "enum" in schema:
#                     print(f"[RULE] {endpoint} parameter '{name}' must be one of {schema['enum']}")

#                 if "minimum" in schema:
#                     print(f"[RULE] {endpoint} parameter '{name}' >= {schema['minimum']}")

#                 if "maximum" in schema:
#                     print(f"[RULE] {endpoint} parameter '{name}' <= {schema['maximum']}")

#             # REQUEST BODY
#             request_body = details.get("requestBody")

#             if request_body:
#                 print(f"[RULE] {endpoint} requires request body")


# def extract_from_yaml(file):

#     with open(file, "r", encoding="utf-8") as f:
#         data = yaml.safe_load(f)

#     extract_rules_from_openapi(data, file)


# def extract_from_json(file):

#     with open(file, "r", encoding="utf-8") as f:
#         data = json.load(f)

#     extract_rules_from_openapi(data, file)


# def extract_from_markdown(file):

#     print(f"\n--- POSSIBLE RULES FROM {file} ---")

#     with open(file, "r", encoding="utf-8") as f:
#         text = f.read()

#     keywords = [
#         "authentication",
#         "authorization",
#         "must",
#         "required",
#         "only",
#         "token",
#         "api key"
#     ]

#     lines = text.split("\n")

#     for line in lines:
#         for k in keywords:
#             if k in line.lower():
#                 print(f"[DOC RULE] {line.strip()}")
#                 break


# def main():

#     for file in os.listdir(folder):

#         if file.endswith(".yaml") or file.endswith(".yml"):
#             extract_from_yaml(os.path.join(folder, file))

#         elif file.endswith(".json"):
#             extract_from_json(os.path.join(folder, file))

#         elif file.endswith(".md"):
#             extract_from_markdown(os.path.join(folder, file))


# if __name__ == "__main__":
#     main()

import os
import yaml
import json

# Folder containing all your API files
FOLDER = "./"  

# Output JSONL file
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "../data/api_rules.jsonl")

def extract_rules_from_openapi(data, filename):
    rules = []
    paths = data.get("paths", {})

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, details in methods.items():
            if not isinstance(details, dict):
                continue

            endpoint = f"{method.upper()} {path}"

            # Authentication rules
            if "security" in details:
                rules.append({
                    "rule_id": f"{filename}_auth_{endpoint}",
                    "endpoint": endpoint,
                    "rule_type": "authentication",
                    "description": "Endpoint requires authentication",
                    "source": filename
                })

            # Parameters
            for param in details.get("parameters", []):
                schema = param.get("schema", {})

                rule_obj = {
                    "rule_id": f"{filename}_param_{endpoint}_{param.get('name')}",
                    "endpoint": endpoint,
                    "rule_type": "parameter",
                    "parameter": param.get("name"),
                    "required": param.get("required", False),
                    "type": schema.get("type"),
                    "enum": schema.get("enum"),
                    "minimum": schema.get("minimum"),
                    "maximum": schema.get("maximum"),
                    "description": param.get("description", ""),
                    "source": filename
                }
                rules.append(rule_obj)

            # Request body exists
            if "requestBody" in details:
                rules.append({
                    "rule_id": f"{filename}_body_{endpoint}",
                    "endpoint": endpoint,
                    "rule_type": "request_body",
                    "description": "Endpoint requires request body",
                    "source": filename
                })

    return rules


def extract_rules_from_markdown(file_path):
    # Optional: capture "security-like" lines from Markdown
    rules = []
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    keywords = ["authentication", "authorization", "must", "required", "only", "token", "api key"]
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if any(k in line.lower() for k in keywords):
            rules.append({
                "rule_id": f"{file_path}_md_{i}",
                "rule_type": "doc_hint",
                "description": line.strip(),
                "source": file_path
            })
    return rules


def load_spec(file_path):
    if file_path.endswith((".yaml", ".yml")):
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    elif file_path.endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def main():
    all_rules = []

    for file in os.listdir(FOLDER):
        full_path = os.path.join(FOLDER, file)

        if file.endswith((".yaml", ".yml", ".json")):
            spec = load_spec(full_path)
            if spec:
                all_rules.extend(extract_rules_from_openapi(spec, file))

        elif file.endswith(".md"):
            all_rules.extend(extract_rules_from_markdown(full_path))

    # Write to JSONL
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for r in all_rules:
            json.dump(r, f)
            f.write("\n")

    print(f"Done! {len(all_rules)} rules written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()