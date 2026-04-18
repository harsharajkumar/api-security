"""
Inference test for the fine-tuned QLoRA adapter.
Run in Colab or any environment with a GPU.

Requirements:
    pip install torch transformers peft bitsandbytes accelerate
"""

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel

# ── Config ────────────────────────────────────────────────────────────────────
BASE_MODEL   = "codellama/CodeLlama-7b-instruct-hf"
ADAPTER_PATH = "./model_folder/checkpoint-531"

SYSTEM_PROMPT = (
    "You are a security-focused code reviewer specializing in API vulnerability "
    "detection and remediation. Analyze the provided code, identify security flaws, "
    "explain the vulnerabilities, and provide a secure version."
)

def make_prompt(body: str) -> str:
    return (
        "<s>[INST] <<SYS>>\n"
        + SYSTEM_PROMPT + "\n<</SYS>>\n\n"
        + body + " [/INST]\n"
    )


# ── Test prompts ───────────────────────────────────────────────────────────────
PROMPTS = {

    # 1. SQL Injection — PHP/Laravel (original)
    "1_sqli_laravel": make_prompt(
        "Analyze the following PHP (Laravel) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : GET\n"
        "Endpoint    : /api/users\n\n"
        "```php\n"
        "Route::get('/api/users', function(Request $r) {\n"
        "    $id = $r->input('id');\n"
        '    return DB::select("SELECT * FROM users WHERE id = $id");\n'
        "});\n"
        "```"
    ),

    # 2. Broken Authentication — Python/Flask (JWT secret hardcoded)
    "2_broken_auth_flask": make_prompt(
        "Analyze the following Python (Flask) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : POST\n"
        "Endpoint    : /api/login\n\n"
        "```python\n"
        "import jwt\n"
        "SECRET = 'secret123'\n\n"
        "@app.route('/api/login', methods=['POST'])\n"
        "def login():\n"
        "    data = request.get_json()\n"
        "    user = User.query.filter_by(username=data['username']).first()\n"
        "    if user and user.password == data['password']:\n"
        "        token = jwt.encode({'user_id': user.id}, SECRET, algorithm='HS256')\n"
        "        return jsonify({'token': token})\n"
        "    return jsonify({'error': 'Invalid credentials'}), 401\n"
        "```"
    ),

    # 3. IDOR — Node.js/Express (insecure direct object reference)
    "3_idor_express": make_prompt(
        "Analyze the following Node.js (Express) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : GET\n"
        "Endpoint    : /api/orders/:id\n\n"
        "```javascript\n"
        "app.get('/api/orders/:id', async (req, res) => {\n"
        "    const order = await Order.findById(req.params.id);\n"
        "    if (!order) return res.status(404).json({ error: 'Not found' });\n"
        "    res.json(order);\n"
        "});\n"
        "```"
    ),

    # 4. Sensitive Data Exposure — Python/Django (password in response)
    "4_data_exposure_django": make_prompt(
        "Analyze the following Python (Django REST Framework) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : GET\n"
        "Endpoint    : /api/profile\n\n"
        "```python\n"
        "class ProfileView(APIView):\n"
        "    def get(self, request):\n"
        "        user = User.objects.get(id=request.query_params.get('id'))\n"
        "        return Response({\n"
        "            'username': user.username,\n"
        "            'email': user.email,\n"
        "            'password': user.password,\n"
        "            'ssn': user.ssn,\n"
        "            'credit_card': user.credit_card,\n"
        "        })\n"
        "```"
    ),

    # 5. Command Injection — Python/Flask (OS command via user input)
    "5_cmd_injection_flask": make_prompt(
        "Analyze the following Python (Flask) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : POST\n"
        "Endpoint    : /api/ping\n\n"
        "```python\n"
        "import os\n\n"
        "@app.route('/api/ping', methods=['POST'])\n"
        "def ping():\n"
        "    host = request.json.get('host')\n"
        "    result = os.popen(f'ping -c 4 {host}').read()\n"
        "    return jsonify({'output': result})\n"
        "```"
    ),

    # 6. Mass Assignment — Node.js/Express (unrestricted body fields)
    "6_mass_assignment_express": make_prompt(
        "Analyze the following Node.js (Express) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : PUT\n"
        "Endpoint    : /api/users/:id\n\n"
        "```javascript\n"
        "app.put('/api/users/:id', async (req, res) => {\n"
        "    const user = await User.findByIdAndUpdate(\n"
        "        req.params.id,\n"
        "        req.body,\n"
        "        { new: true }\n"
        "    );\n"
        "    res.json(user);\n"
        "});\n"
        "```"
    ),

    # 7. XSS via API response — PHP (unescaped output)
    "7_xss_php": make_prompt(
        "Analyze the following PHP API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : GET\n"
        "Endpoint    : /api/search\n\n"
        "```php\n"
        "Route::get('/api/search', function(Request $request) {\n"
        "    $query = $request->input('q');\n"
        "    $results = Product::whereRaw(\"name LIKE '%$query%'\")->get();\n"
        "    return response()->json([\n"
        "        'query' => $query,\n"
        "        'results' => $results\n"
        "    ]);\n"
        "});\n"
        "```"
    ),

    # 8. Broken Access Control — Python/Flask (no role check on admin route)
    "8_broken_access_flask": make_prompt(
        "Analyze the following Python (Flask) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : DELETE\n"
        "Endpoint    : /api/admin/users/<user_id>\n\n"
        "```python\n"
        "@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])\n"
        "@login_required\n"
        "def delete_user(user_id):\n"
        "    user = User.query.get_or_404(user_id)\n"
        "    db.session.delete(user)\n"
        "    db.session.commit()\n"
        "    return jsonify({'message': 'User deleted'})\n"
        "```"
    ),

    # 9. Rate Limiting Missing — Node.js/Express (login brute force)
    "9_no_rate_limit_express": make_prompt(
        "Analyze the following Node.js (Express) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : POST\n"
        "Endpoint    : /api/auth/login\n\n"
        "```javascript\n"
        "app.post('/api/auth/login', async (req, res) => {\n"
        "    const { email, password } = req.body;\n"
        "    const user = await User.findOne({ email });\n"
        "    if (!user || !bcrypt.compareSync(password, user.password)) {\n"
        "        return res.status(401).json({ error: 'Invalid credentials' });\n"
        "    }\n"
        "    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);\n"
        "    res.json({ token });\n"
        "});\n"
        "```"
    ),

    # 10. XML External Entity (XXE) — Java/Spring
    "10_xxe_spring": make_prompt(
        "Analyze the following Java (Spring Boot) API endpoint for security vulnerabilities.\n\n"
        "HTTP Method : POST\n"
        "Endpoint    : /api/import\n\n"
        "```java\n"
        "@PostMapping(\"/api/import\")\n"
        "public ResponseEntity<?> importData(@RequestBody String xmlData) throws Exception {\n"
        "    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n"
        "    DocumentBuilder builder = factory.newDocumentBuilder();\n"
        "    Document doc = builder.parse(new InputSource(new StringReader(xmlData)));\n"
        "    String name = doc.getElementsByTagName(\"name\").item(0).getTextContent();\n"
        "    return ResponseEntity.ok(Map.of(\"imported\", name));\n"
        "}\n"
        "```"
    ),
}


# ── Load tokenizer ─────────────────────────────────────────────────────────────
print("Loading tokenizer...")
tok = AutoTokenizer.from_pretrained(BASE_MODEL, use_fast=False)
tok.pad_token = tok.eos_token

# ── Load base model in 4-bit ───────────────────────────────────────────────────
print("Loading base model in 4-bit...")
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)

# ── Attach QLoRA adapter ───────────────────────────────────────────────────────
print(f"Loading adapter from {ADAPTER_PATH}...")
model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
model.eval()


# ── Run all prompts ────────────────────────────────────────────────────────────
def run(prompt: str) -> str:
    inputs = tok(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=512,
            do_sample=True,
            temperature=0.3,
            top_p=0.9,
            repetition_penalty=1.3,
            pad_token_id=tok.eos_token_id,
        )
    generated = out[0][inputs["input_ids"].shape[1]:]
    return tok.decode(generated, skip_special_tokens=True)


for name, prompt in PROMPTS.items():
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print('='*60)
    print(run(prompt))
    print()
