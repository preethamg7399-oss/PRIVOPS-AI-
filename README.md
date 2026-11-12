# PRIVOPS: Purpose-Aware AI Privacy Gateway with Incident Memory

[![Hackathon](https://img.shields.io/badge/MINEARENA_1.0-PS--02-blue.svg)](https://minearena.ai)
[![Team](https://img.shields.io/badge/Team-AxiomX-indigo.svg)](#)
[![Compliance](https://img.shields.io/badge/Compliance-DPDP_Act_2023_Ready-emerald.svg)](#)
[![Leakage](https://img.shields.io/badge/Outbound_PII_Leakage-0.0%25-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-13%20Passed-success.svg)](#)

> **"Your Data. Your Control. Your Privacy."**  
> *PRIVOPS does not stop organizations from using AI. It makes AI usage safer by ensuring that personal information is protected before it reaches external AI services.*

---

## 1. Executive Summary

Enterprise adoption of external Large Language Models (LLMs) such as OpenAI GPT-4, Google Gemini, Anthropic Claude, and Groq creates severe privacy and regulatory compliance liabilities. Employees routinely paste customer records containing **Aadhaar numbers, PANs, GSTINs, phone numbers, email addresses, and residential locations** into public AI prompts.

Under India's **Digital Personal Data Protection (DPDP) Act, 2023** and upcoming Rules 2025, unauthorized disclosure, purpose violations, and lack of reasonable security safeguards carry severe penalties.

**PRIVOPS** acts as an intelligent, purpose-aware security gateway intercepting enterprise traffic to external LLMs. It replaces sensitive personal data with cryptographically secure placeholders, verifies **zero raw-PII leakage** before transmission, and reinserts original values locally upon return—all while maintaining an immutable **Incident Memory** and **Audit Trail**.

---

## 2. System Architecture & 10-Step Lifecycle

```
USER / ENTERPRISE APPLICATION
           │
           ▼
     PRIVOPS GATEWAY
           │
           ▼  [Step 1] Intercept Outbound Request
    PURPOSE VALIDATION (DPDP Sec 6 Purpose Check & Data Minimization)
           │
           ▼  [Step 2] Hybrid PII Detection Engine (Presidio + spaCy + Verhoeff)
    SENSITIVE DATA CLASSIFICATION (Aadhaar, PAN, GSTIN, Phone, Email, Address)
           │
           ▼  [Step 3] Smart Tokenization (<PERSON_1>, <AADHAAR_1>, <PAN_1>)
       TOKENIZATION
           │
           ▼  [Step 4] Request-Specific AES-128 Encryption
      ENCRYPTED VAULT (Local Memory / At-Rest Isolation)
           │
           ▼  [Step 5] Dual-Stage Outbound Scan
     ZERO-LEAK GUARD (Aborts & logs incident if any raw PII leaks)
           │
           ▼  [Step 6] Forward Sanitized Payload
       EXTERNAL LLM (OpenAI / Compatible API / Pluggable Fallback)
           │
           ▼  [Step 7] Receive AI-Generated Response
     AI-GENERATED RESPONSE (Containing tokens)
           │
           ▼  [Step 8] Local Decryption & Safe Restoration
    SECURE REINSERTION (Handles reordered tokens, flags hallucinations)
           │
           ▼  [Step 9] Return Restored Response
       USER RESPONSE
           │
           ▼  [Step 10] Record Audit Trail & Incident Memory
    AUDIT & INCIDENT LOG (SQLite, Zero Raw PII Retained)
```

---

## 3. Key Features

### 🇮🇳 1. Intelligent Indian PII Detection
- **Aadhaar Number**: Full Verhoeff checksum algorithm (dihedral group $D_5$) validation. Eliminates false positives from arbitrary 12-digit numbers.
- **PAN (Permanent Account Number)**: Structure validation (`[A-Z]{5}[0-9]{4}[A-Z]`) with 4th character taxpayer categorization (Individual, Company, Firm, HUF, Trust).
- **GSTIN**: 15-character Goods and Services Tax ID with state-code decomposition.
- **Voter ID (EPIC)** & **Passport**: 10-digit EPIC format and standard passport formats.
- **Indian Phone Numbers**: `+91`, `0`, and 10-digit mobile numbers starting with 6, 7, 8, or 9.
- **Email, Bank Account, IFSC, & Addresses**: Context-aware extraction with street, pin code, and major Indian cities.
- **Names**: Microsoft Presidio + spaCy NER with contextual enterprise headers.

### 🏷️ 2. Smart Consistent Tokenization
- Consistent token substitution: If *"Rahul Kumar"* appears 3 times in a document, all occurrences deterministically map to `<PERSON_1>`.
- Reverse-span character replacement preserves index integrity.

### 🔐 3. Encrypted Local Privacy Vault
- Request-specific AES-128-CBC / Fernet encryption with PBKDF2HMAC key derivation.
- In-memory/at-rest isolation: **Raw token mappings NEVER leave the gateway memory.**
- Automatic TTL expiration and secure zero-overwrite memory buffer deletion.

### 🎯 4. Purpose-Aware Privacy Engine (DPDP Section 6)
- Configurable business purpose policies (`config/policies.json`):
  - **Customer Support**: Allowed: Name, Phone, Email. Blocked: Aadhaar, Bank Account, Passport.
  - **Loan Processing**: Allowed: Name, PAN, Bank, Phone, Address. Masked: Aadhaar. Blocked: Voter ID, Passport.
  - **Marketing**: Strictly Blocked: Aadhaar, PAN, Bank Account, Passport, Address.
  - **Fraud Investigation**: Allowed with strict tokenization: PAN, Account, GSTIN, Aadhaar.
- Automatic request blocking when an unpermitted PII category is detected for a given purpose.

### 🛡️ 5. Zero-Leakage Verification (LeakGuard)
- Pre-outbound scan compares outbound text against raw vault values.
- Re-scans outbound text with PII recognizers to ensure no un-tokenized sensitive substrings remain.
- **Result:** Proven 0.00% outbound raw-PII leakage rate.

### 🔄 6. Secure Local Reinsertion
- Replaces `<TOKEN_N>` placeholders with decrypted original values upon response receipt.
- Robust against reordered tokens and paraphrased AI responses.
- Detects and flags hallucinated or unrecognized placeholders (e.g. `<PERSON_99>`) without inventing data.

### 🧠 7. Security Incident Memory
- SQLite-backed incident logger tracking violations, severity, purpose, and client IP/ID.
- **Pattern Tracker**: Detects repeated violations (>2 within 1 hour) to flag recurring anomalous attack patterns.
- Strict security rule: **Zero raw personal information stored in incident logs.**

### 📊 8. Audit Dashboard & Compliance Analytics
- Aggregates total requests, entities detected, sanitized vs blocked, leakage incidents prevented, and average latency.
- Plotly interactive distribution charts and DPDP Act 2023 alignment matrix.

### 🤖 9. Pluggable LLM Architecture
- Supports OpenAI, Google Gemini, Groq, and local Ollama/vLLM endpoints via `OPENAI_API_KEY` and `OPENAI_API_BASE`.
- Includes an offline **Local Enterprise Simulator** that contextually generates domain-specific responses retaining token placeholders so demos never fail due to network or missing keys.

### 🖥️ 10. Three-Pane Demonstration Interface (Streamlit)
- **Panel A**: Original Enterprise Input (with detected PII table).
- **Panel B**: Protected Outbound Payload (sanitized tokens + vault mapping).
- **Panel C**: Final User Response (safely restored original values + reinsertion diff).

---

## 4. Measured Evaluation Benchmark (50 Enterprise Documents)

Evaluated across **50 synthetic Indian enterprise documents** spanning Banking, Customer Support, Vendor Management, Marketing, and Fraud Audit:

| Evaluation Metric | Measured Result | Benchmark Standard | Status |
|---|---|---|---|
| **Outbound PII Leakage Rate** | **0.00%** | **0.0% (Zero Leakage)** | ✅ **PASSED** |
| **Tokenization Accuracy** | **100.0%** | **100%** | ✅ **PASSED** |
| **Reinsertion Accuracy** | **100.0%** | **> 98%** | ✅ **PASSED** |
| **Request Blocking Accuracy** | **100.0%** | **100%** | ✅ **PASSED** |
| **PII Detection Recall** | **90.00%** | **> 85%** | ✅ **PASSED** |
| **PII Detection Precision** | **86.82%** | **> 85%** | ✅ **PASSED** |
| **Average Processing Latency** | **154.56 ms** | **< 500 ms** | ⚡ **OPTIMAL** |

*Measured on 50 documents via `python evaluate.py`.*

---

## 5. Project Structure

```
PRIVOPS/
│
├── backend/
│   ├── __init__.py
│   ├── main.py                  # FastAPI REST gateway application
│   ├── gateway.py               # Core 10-step gateway orchestrator
│   ├── detector.py              # Hybrid PII detection engine (Presidio + spaCy)
│   ├── recognizers.py           # Indian PII recognizers & Verhoeff checksum
│   ├── tokenizer.py             # Deterministic smart tokenization
│   ├── vault.py                 # Encrypted Local Privacy Vault (AES-128 Fernet)
│   ├── purpose_engine.py        # DPDP Purpose Limitation & Data Minimization
│   ├── leak_guard.py            # Zero-Leakage outbound verification
│   ├── reinsertion.py           # Safe local response reinsertion
│   ├── incident_manager.py      # SQLite Incident Memory & Pattern Tracker
│   ├── audit.py                 # SQLite Audit logger & metrics telemetry
│   └── llm_client.py            # Pluggable LLM client & offline fallback
│
├── frontend/
│   └── dashboard.py             # Streamlit Three-Pane cybersecurity dashboard
│
├── dataset/
│   ├── __init__.py
│   └── synthetic_data_generator.py # 50+ annotated Indian enterprise documents
│
├── tests/
│   ├── __init__.py
│   ├── test_detection.py        # Verhoeff, PAN, GSTIN, Phone, Email tests
│   ├── test_tokenization.py     # Tokenization & Vault encryption tests
│   ├── test_leak_guard.py       # Zero-Leakage verification tests
│   └── test_reinsertion.py      # Token restoration & hallucination tests
│
├── config/
│   └── policies.json            # Purpose-aware DPDP minimization policies
│
├── evaluate.py                  # 50-document evaluation benchmark runner
├── evaluation_report.json       # Generated benchmark metrics output
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## 6. 5-Minute Hackathon Demonstration Scenario

To present PRIVOPS to the judges in 5 minutes:

1. **Step 1: Open the Dashboard**:
   ```bash
   streamlit run frontend/dashboard.py
   ```
2. **Step 2: Demonstrate Normal Loan Processing Flow**:
   - Select `Scenario 1: Customer Loan Application (Aadhaar, PAN, Bank, Address)`.
   - Purpose: `loan_processing`. Click **🚀 Process Through PRIVOPS Gateway**.
   - Show **Panel A**: Original prompt containing Rahul Sharma's Aadhaar, PAN, and Bank details.
   - Show **Panel B**: Outbound data showing `<PERSON_1>`, `<AADHAAR_1>`, `<PAN_1>`, `<BANK_ACCOUNT_1>`. Note the **0.00% Outbound Leakage Seal**.
   - Show **Panel C**: External LLM response with original credentials restored locally in real-time.
3. **Step 3: Demonstrate Intentional DPDP Purpose Breach**:
   - Select `Scenario 3: Intentional DPDP Purpose Breach (Aadhaar in Marketing)`.
   - Purpose: `marketing`. Click **🚀 Process**.
   - Watch the gateway immediately **BLOCK** the request with red status banner:  
     `DPDP Purpose Violation: Marketing strictly blocks Aadhaar & PAN under Section 6 Data Minimization.`
4. **Step 4: Demonstrate Zero-Leakage Verification (LeakGuard)**:
   - Check the box `⚠️ Simulate Outbound Leak`.
   - Click **🚀 Process**.
   - Watch LeakGuard instantly catch the tainted payload, abort external transmission, and log a **CRITICAL** incident.
5. **Step 5: Show Incident Memory & Audit Analytics**:
   - Navigate to `🚨 Security Incident Memory` to view the logged incident and recurring anomaly detection.
   - Navigate to `📊 DPDP Audit & Analytics` to show live Plotly charts and DPDP compliance mapping.
6. **Step 6: Show Benchmark Verification**:
   - Navigate to `📈 50-Doc Benchmark Evaluation` to show the verified measured results (100% tokenization, 0% leakage, 154ms latency).

---

## 7. Installation & Quickstart

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Windows / Linux / macOS

### Setup
```bash
# Clone the repository
git clone https://github.com/axiomx/privops.git
cd privops

# Install dependencies
pip install -r requirements.txt

# Run Unit Tests (13/13 Pass)
python -m pytest tests -v

# Run the 50-Document Evaluation Benchmark
python evaluate.py

# Launch the FastAPI Gateway
python -m uvicorn backend.main:app --port 8000 --reload

# Launch the Streamlit Enterprise Dashboard (in separate terminal)
streamlit run frontend/dashboard.py
```

---

## 8. DPDP Act 2023 & Rules 2025 Compliance Mapping

| DPDP Principle | Statutory Reference | PRIVOPS Technical Implementation |
|---|---|---|
| **Purpose Limitation** | Section 6(1) | `PurposeEngine` validates prompt context against permitted categories in `config/policies.json`. |
| **Data Minimization** | Section 6(2) | Unnecessary identifiers (Aadhaar, Passport) blocked or masked before AI transmission. |
| **Security Safeguards** | Section 8(5) | Encrypted Vault (`AES-128 Fernet`) isolates mappings locally in memory; zero outbound transmission. |
| **Leakage Interception** | Section 8(6) | `LeakGuard` performs dual-stage verification pre-outbound to ensure 0% raw PII escape. |
| **Breach Incident Memory** | Section 8(6) | `IncidentManager` logs policy violations with severity and recurring anomaly detection without storing raw PII. |
| **Storage Limitation** | Section 8(7) | Configurable TTL automatic expiration and zero-overwrite memory buffer deletion. |

---

## 9. Hackathon Team & Acknowledgments

- **Hackathon:** MINEARENA 1.0
- **Problem Statement:** PS-02 – DPDP-Ready Privacy Gateway for Enterprise LLMs
- **Team:** AxiomX
- **Tagline:** *Your Data. Your Control. Your Privacy.*

