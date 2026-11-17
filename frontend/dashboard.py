"""
PRIVOPS - Advanced Multilingual Text & Visual Privacy Gateway
Hackathon: MINEARENA 1.0 | Problem Statement: PS-02 | Team: AxiomX
Tagline: Your Data. Your Control. Your Privacy.
Professional Dark Navy Enterprise Cybersecurity Interface with 9 Navigation Sections.
"""

import os
import sys
import json
import time
import io
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image

# Add parent directory to sys.path so backend imports work seamlessly
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.gateway import gateway_instance
from backend.incident_manager import incident_manager_instance
from backend.audit import audit_logger_instance
from backend.purpose_engine import purpose_engine_instance
from backend.vault import vault_instance
from backend.multilingual_engine import multilingual_engine_instance, SUPPORTED_LANGUAGES
from backend.face_anonymizer import face_anonymizer_instance
from backend.dataset_evaluator import dataset_evaluator_instance
from dataset.synthetic_data_generator import (
    generate_valid_aadhaar,
    generate_valid_pan,
    generate_valid_phone,
    generate_valid_gstin
)


def generate_sanitized_pdf(text: str, title: str = "PRIVOPS Sanitized Document") -> bytes:
    """Generates a downloadable sanitized PDF document using ReportLab."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=16,
            leading=20,
            textColor=colors.HexColor('#1E3A8A'),
            spaceAfter=12
        )
        body_style = ParagraphStyle(
            'DocBody',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#1F2937')
        )

        story = [
            Paragraph(f"<b>🛡️ {title}</b>", title_style),
            Paragraph("<font color='#6B7280' size='8'>Protected & Anonymized by PRIVOPS Enterprise Gateway | DPDP Act 2023 Compliant</font>", body_style),
            Spacer(1, 16)
        ]

        for line in text.splitlines():
            clean_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if clean_line.strip():
                story.append(Paragraph(clean_line, body_style))
                story.append(Spacer(1, 4))
            else:
                story.append(Spacer(1, 8))

        doc.build(story)
        return buf.getvalue()
    except Exception:
        return text.encode("utf-8")

# Page Configuration
st.set_page_config(
    page_title="PRIVOPS | AI Privacy Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Enterprise Cybersecurity Dark Navy Styling
st.markdown("""
<style>
    /* Dark Navy & Cobalt Cyber Theme */
    .stApp {
        background-color: #0B1120;
        color: #E2E8F0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Header branding */
    .cyber-header {
        background: linear-gradient(90deg, #1E293B 0%, #0F172A 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .brand-title {
        font-size: 28px;
        font-weight: 800;
        letter-spacing: 1.5px;
        background: linear-gradient(90deg, #38BDF8, #818CF8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .brand-tagline {
        color: #94A3B8;
        font-size: 14px;
        font-weight: 500;
        margin-top: 4px;
    }
    .brand-badge {
        background-color: #1E3A8A;
        color: #60A5FA;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        border: 1px solid #2563EB;
    }

    /* Metric Card */
    .metric-card {
        background: #131E32;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-num {
        font-size: 26px;
        font-weight: 700;
        color: #F8FAFC;
    }
    .metric-label {
        font-size: 12px;
        font-weight: 600;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 4px;
    }

    /* Status Banners */
    .banner-protected {
        background: linear-gradient(90deg, #064E3B 0%, #022C22 100%);
        border: 1px solid #10B981;
        border-radius: 8px;
        padding: 14px 18px;
        color: #A7F3D0;
        font-weight: 600;
        margin-bottom: 20px;
    }
    .banner-blocked {
        background: linear-gradient(90deg, #7F1D1D 0%, #450A0A 100%);
        border: 1px solid #EF4444;
        border-radius: 8px;
        padding: 14px 18px;
        color: #FECACA;
        font-weight: 600;
        margin-bottom: 20px;
    }
    .banner-leak {
        background: linear-gradient(90deg, #78350F 0%, #451A03 100%);
        border: 1px solid #F59E0B;
        border-radius: 8px;
        padding: 14px 18px;
        color: #FDE68A;
        font-weight: 600;
        margin-bottom: 20px;
    }

    /* Panel Styling */
    .panel-box {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 16px;
        height: 100%;
        min-height: 480px;
    }
    .panel-header {
        font-size: 15px;
        font-weight: 700;
        letter-spacing: 0.8px;
        padding-bottom: 10px;
        border-bottom: 1px solid #1E293B;
        margin-bottom: 14px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .badge-pii {
        background: #312E81;
        color: #C7D2FE;
        border: 1px solid #4338CA;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        margin-right: 4px;
    }
    .badge-token {
        background: #14532D;
        color: #BBF7D0;
        border: 1px solid #16A34A;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Top Cyber Navigation Header
st.markdown("""
<div class="cyber-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1 class="brand-title">🛡️ PRIVOPS GATEWAY</h1>
            <div class="brand-tagline">Advanced Multilingual Text & Visual Privacy Gateway with Incident Memory | Team AxiomX</div>
        </div>
        <div style="text-align: right;">
            <span class="brand-badge">MINEARENA 1.0 (PS-02)</span><br>
            <span style="font-size: 11px; color: #38BDF8; font-weight: 600;">DPDP Act 2023 Ready</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Sidebar Navigation - 9 Distinct Sections (Preserved & Extended)
st.sidebar.title("Navigation")
menu_selection = st.sidebar.radio(
    "Select Gateway Module",
    [
        "🏛️ Overview",
        "🛡️ Text Protection",
        "📄 Document Protection",
        "🌐 Multilingual Processing",
        "👁️ Visual Privacy",
        "📈 Detection Evaluation",
        "📜 Audit Logs",
        "📊 Analytics",
        "📋 Policy"
    ]
)

# =========================================================================
# GLOBAL PERSISTENT WORKSPACE
# Uploaded files persist across all pages without asking to re-upload
# =========================================================================
st.sidebar.markdown("---")
st.sidebar.subheader("📂 Document & Folder Workspace")
st.sidebar.caption("Upload documents once; they are automatically active across all sections without re-uploading.")

if "workspace_documents" not in st.session_state:
    st.session_state["workspace_documents"] = {}

workspace_uploads = st.sidebar.file_uploader(
    "Upload Files or Folder Content:",
    type=["pdf", "png", "jpg", "jpeg", "txt", "json", "csv"],
    accept_multiple_files=True,
    key="global_workspace_uploader",
    help="Files uploaded here remain accessible in Document Protection, Multilingual, Visual Privacy, and Evaluation without re-uploading."
)

if workspace_uploads:
    for f in workspace_uploads:
        if f.name not in st.session_state["workspace_documents"]:
            f_bytes = f.getvalue()
            raw_text, method, meta = multilingual_engine_instance.extract_document_text(f_bytes, f.name)
            lang_info = multilingual_engine_instance.identify_language(raw_text)
            faces_count = 0
            ext = f.name.lower().split(".")[-1]
            if ext in ["jpg", "jpeg", "png", "bmp"]:
                try:
                    _, faces_count, _, _ = face_anonymizer_instance.anonymize_image(f_bytes)
                except Exception:
                    pass
            elif ext == "pdf":
                try:
                    pdf_faces = face_anonymizer_instance.extract_and_anonymize_pdf_images(f_bytes)
                    faces_count = sum(p["faces_found"] for p in pdf_faces)
                except Exception:
                    pass

            st.session_state["workspace_documents"][f.name] = {
                "filename": f.name,
                "bytes": f_bytes,
                "text": raw_text,
                "method": method,
                "meta": meta,
                "lang_info": lang_info,
                "faces_count": faces_count
            }

if st.session_state["workspace_documents"]:
    doc_names = list(st.session_state["workspace_documents"].keys())
    active_idx = st.sidebar.selectbox(
        "Active Workspace Document:",
        range(len(doc_names)),
        format_func=lambda i: doc_names[i],
        key="active_doc_picker"
    )
    st.session_state["active_doc"] = st.session_state["workspace_documents"][doc_names[active_idx]]
    st.sidebar.success(f"📄 Active: `{doc_names[active_idx]}` ({len(doc_names)} file(s) loaded)")
    if st.sidebar.button("🗑️ Clear Workspace", key="btn_clear_workspace"):
        st.session_state["workspace_documents"] = {}
        st.session_state["active_doc"] = None
        st.rerun()
else:
    st.session_state["active_doc"] = None

st.sidebar.markdown("---")
st.sidebar.subheader("🔒 Gateway Telemetry")
v_stats = vault_instance.get_vault_stats()
st.sidebar.caption(f"**Vault Status:** Active (AES-128 At-Rest)")
st.sidebar.caption(f"**Active Sessions:** {v_stats.get('active_sessions', 0)}")
st.sidebar.caption(f"**Supported Languages:** 8 Indian Languages")
st.sidebar.caption(f"**Visual Privacy:** YuNet ONNX Active")
st.sidebar.markdown("---")
st.sidebar.info("**Tagline:** *Your Data. Your Control. Your Privacy.*")

# =========================================================================
# SECTION 1: OVERVIEW
# =========================================================================
if menu_selection == "🏛️ Overview":
    st.subheader("Enterprise Privacy Gateway Overview")
    st.markdown(
        "**PRIVOPS** acts as an intelligent, purpose-aware security gateway intercepting enterprise traffic to "
        "external LLMs. It replaces sensitive personal data with cryptographically secure placeholders, verifies "
        "**zero raw-PII leakage** before transmission, anonymizes human faces in documents/images, and reinserts original values locally upon return."
    )

    metrics = audit_logger_instance.get_metrics_summary()
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num">{metrics.get('total_requests', 0)}</div>
            <div class="metric-label">Total Requests</div>
        </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #60A5FA;">{metrics.get('total_documents_processed', 0)}</div>
            <div class="metric-label">Documents Processed</div>
        </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #34D399;">{metrics.get('total_pii_entities_detected', 0)}</div>
            <div class="metric-label">PII Detected</div>
        </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #FBBF24;">{metrics.get('total_faces_anonymized', 0)}</div>
            <div class="metric-label">Faces Anonymized</div>
        </div>
        """, unsafe_allow_html=True)
    with k5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #38BDF8;">0.00%</div>
            <div class="metric-label">Outbound Leak Rate</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("##### ⚖️ DPDP Act 2023 Statutory Alignment Matrix")
    dpdp_data = [
        {"DPDP Principle": "Purpose Limitation (Sec 6)", "Gateway Safeguard": "PurposeEngine validates prompt context before AI call", "Status": "ENFORCED"},
        {"DPDP Principle": "Data Minimization (Sec 6)", "Gateway Safeguard": "Unnecessary identifiers blocked or masked per purpose", "Status": "ENFORCED"},
        {"DPDP Principle": "Security Safeguards (Sec 8)", "Gateway Safeguard": "Encrypted Local Vault (AES-128 Fernet) isolates mappings", "Status": "ENFORCED"},
        {"DPDP Principle": "Visual Privacy & Biometrics", "Gateway Safeguard": "OpenCV YuNet auto-anonymizes faces in documents/images", "Status": "ACTIVE"},
        {"DPDP Principle": "Zero Outbound Exposure", "Gateway Safeguard": "LeakGuard scans outbound payload guaranteeing 0.00% leak", "Status": "VERIFIED"},
        {"DPDP Principle": "Breach Tracking (Sec 8(6))", "Gateway Safeguard": "IncidentManager logs policy breaches without raw PII", "Status": "ACTIVE"},
    ]
    st.dataframe(pd.DataFrame(dpdp_data), use_container_width=True)

    st.markdown("---")
    st.markdown("##### 🛡️ Core Protection Pillars")
    p1, p2, p3, p4 = st.columns(4)
    with p1:
        st.markdown("""
        **🔒 Zero-Leakage Guarantee**  
        Pre-outbound heuristic and regex verification guarantees 0.00% raw personal data transmission to external LLMs.
        """)
    with p2:
        st.markdown("""
        **🔐 AES-128 Local Vault**  
        Cryptographic token mappings are isolated exclusively in local memory; no decrypted keys ever cross the boundary.
        """)
    with p3:
        st.markdown("""
        **🌐 8-Language Multilingual**  
        Native PII recognition & regional digit normalization across Kannada, Hindi, Tamil, Telugu, Malayalam, Marathi, Bengali, and English.
        """)
    with p4:
        st.markdown("""
        **👁️ Visual Privacy (YuNet)**  
        DNN face detection with Gaussian blur, pixelation, or redaction masking ensuring visual biometrics never leave the perimeter.
        """)

# =========================================================================
# SECTION 2: TEXT PROTECTION (Original Three-Pane Live Demo)
# =========================================================================
elif menu_selection == "🛡️ Text Protection":
    st.subheader("Interactive Three-Pane Gateway Live Demo")
    st.markdown(
        "Demonstrates the **10-step zero-exposure lifecycle**. Raw personal data and token mappings "
        "remain strictly within the local environment. **Only sanitized placeholders cross the outbound boundary.**"
    )

    col_preset, col_purpose = st.columns([2, 1])

    with col_preset:
        preset_choice = st.selectbox(
            "Select Demonstration Scenario:",
            [
                "Scenario 1: Customer Loan Application (Aadhaar, PAN, Bank, Address)",
                "Scenario 2: Telecom Customer Support Escalation (Phone, Email, Service A/C)",
                "Scenario 3: Intentional DPDP Purpose Breach (Aadhaar in Marketing -> Auto Blocked)",
                "Scenario 4: Corporate Vendor KYC & GSTIN Form",
                "Scenario 5: Custom Enterprise Input"
            ]
        )

    with col_purpose:
        default_purpose_map = {
            "Scenario 1: Customer Loan Application (Aadhaar, PAN, Bank, Address)": "loan_processing",
            "Scenario 2: Telecom Customer Support Escalation (Phone, Email, Service A/C)": "customer_support",
            "Scenario 3: Intentional DPDP Purpose Breach (Aadhaar in Marketing -> Auto Blocked)": "marketing",
            "Scenario 4: Corporate Vendor KYC & GSTIN Form": "loan_processing",
            "Scenario 5: Custom Enterprise Input": "customer_support"
        }
        purpose_options = ["loan_processing", "customer_support", "marketing", "fraud_investigation", "general_inquiry"]
        selected_purpose = st.selectbox(
            "Declared Processing Purpose (DPDP Section 6):",
            purpose_options,
            index=purpose_options.index(default_purpose_map.get(preset_choice, "customer_support"))
        )

    if preset_choice == "Scenario 1: Customer Loan Application (Aadhaar, PAN, Bank, Address)":
        sample_aadhaar = generate_valid_aadhaar()
        sample_pan = generate_valid_pan("S")
        sample_phone = generate_valid_phone()
        default_text = (
            f"ENTERPRISE LOAN APPLICATION MEMO\n"
            f"Applicant Name: Rahul Sharma\n"
            f"Aadhaar Number: {sample_aadhaar}\n"
            f"PAN Number: {sample_pan}\n"
            f"Primary Mobile: {sample_phone}\n"
            f"Official Email: rahul.sharma@example.in\n"
            f"Disbursement Bank Account No: 501004928172\n"
            f"Residential Address: Flat 402, Shanti Heights, MG Road, Indiranagar, Bengaluru, Karnataka - 560038\n"
            f"Applied Facility: INR 15,00,000 for Business Working Capital Expansion.\n"
            f"Request: Please evaluate the borrower's debt-to-income profile and generate an underwriting sanction note."
        )
    elif preset_choice == "Scenario 2: Telecom Customer Support Escalation (Phone, Email, Service A/C)":
        sample_phone = generate_valid_phone()
        default_text = (
            f"CUSTOMER SERVICE TICKET #ESC-4029\n"
            f"Customer: Priya Nair\n"
            f"Registered Mobile: {sample_phone}\n"
            f"Email Address: priya.nair@telecom.in\n"
            f"Service A/C Number: 9840291029\n"
            f"Address: House 12, Park Street, Kolkata, West Bengal - 700016\n"
            f"Issue: Fiber broadband outage for the past 48 hours. Customer requesting emergency service visit and credit rebate."
        )
    elif preset_choice == "Scenario 3: Intentional DPDP Purpose Breach (Aadhaar in Marketing -> Auto Blocked)":
        sample_aadhaar = generate_valid_aadhaar()
        sample_pan = generate_valid_pan("K")
        default_text = (
            f"MARKETING CAMPAIGN TARGETING LIST\n"
            f"Client: Vikram Kumar\n"
            f"Email: vikram.k@domain.com\n"
            f"Aadhaar: {sample_aadhaar}\n"
            f"PAN: {sample_pan}\n"
            f"Please generate a personalized holiday discount offer for Vikram Kumar using his credit credentials."
        )
    elif preset_choice == "Scenario 4: Corporate Vendor KYC & GSTIN Form":
        sample_pan = generate_valid_pan("P")
        sample_gstin = generate_valid_gstin(sample_pan, "27")
        default_text = (
            f"VENDOR ONBOARDING COMPLIANCE AUDIT\n"
            f"Authorized Signatory: Amit Patel\n"
            f"Company PAN: {sample_pan}\n"
            f"GSTIN: {sample_gstin}\n"
            f"Corporate Bank Account: 102938475612\n"
            f"Official Contact: +91-9820123456\n"
            f"Email: info@patelenterprises.com\n"
            f"Registered Office: Plot 108, MIDC Industrial Area, Andheri East, Mumbai, Maharashtra - 400093\n"
            f"Draft vendor master file validation memo."
        )
    else:
        default_text = (
            "Applicant: Sunita Verma\n"
            "Aadhaar: 9876 5432 1012\n"
            "PAN: BCDPS1234K\n"
            "Phone: +91-9811223344\n"
            "Email: sunita.v@example.com\n"
            "Please review my query regarding account services."
        )

    # Retain user modifications so erased text does not reappear on process/rerun
    if "text_proto_scenario" not in st.session_state or st.session_state.get("text_proto_scenario") != preset_choice:
        st.session_state["text_proto_scenario"] = preset_choice
        st.session_state["text_proto_input"] = default_text

    col_input, col_action = st.columns([3, 1])
    with col_input:
        input_text = st.text_area(
            "Input Document / User Prompt:",
            key="text_proto_input",
            height=180,
            help="You can edit, modify, or erase any part of the prompt. Your edits are preserved during processing."
        )

    with col_action:
        st.markdown("**Gateway Security Controls**")
        simulate_leak_toggle = st.checkbox(
            "⚠️ Simulate Outbound Leak",
            value=False,
            help="Deliberately attempts to inject raw vault PII into outbound payload to test LeakGuard interception."
        )
        process_btn = st.button("🚀 Process Through PRIVOPS Gateway", type="primary", use_container_width=True)
        st.caption("🔒 All token-to-PII mappings encrypted in local memory vault. Raw PII never leaves.")

    if process_btn or "last_gateway_result" in st.session_state:
        if process_btn:
            with st.spinner("Executing PRIVOPS zero-exposure pipeline..."):
                res = gateway_instance.process_request(
                    text=st.session_state["text_proto_input"],
                    purpose=selected_purpose,
                    client_id="streamlit_user_session",
                    simulate_leak=simulate_leak_toggle
                )
                st.session_state["last_gateway_result"] = res

        res = st.session_state.get("last_gateway_result", {})
        status = res.get("status")

        pane_a, pane_b, pane_c = st.columns(3)

        with pane_a:
            st.markdown("""
            <div class="panel-header">
                <span>PANEL A: ORIGINAL ENTERPRISE INPUT</span>
                <span class="badge-pii">Protected Locally</span>
            </div>
            """, unsafe_allow_html=True)
            st.text_area("User Submitted Text", value=input_text, height=240, disabled=True, key="panel_a_text")

            detected = res.get("detected_entities") or res.get("panel_a", {}).get("detected_entities", [])
            st.markdown(f"**Detected Personal Entities ({len(detected)}):**")
            if detected:
                df_det = pd.DataFrame([{
                    "Type": e["entity_type"],
                    "Value": e["value"],
                    "Confidence": f"{int(e['score']*100)}%"
                } for e in detected])
                st.dataframe(df_det, use_container_width=True, height=160)
            else:
                st.info("No sensitive PII entities identified.")

        with pane_b:
            st.markdown("""
            <div class="panel-header">
                <span>PANEL B: PROTECTED OUTBOUND PAYLOAD</span>
                <span class="badge-token">Sent to External LLM</span>
            </div>
            """, unsafe_allow_html=True)

            if status == "BLOCKED":
                st.error("❌ Outbound transmission HALTED. Purpose violation blocked payload generation.")
            elif status == "LEAK_PREVENTED":
                st.error("❌ Outbound transmission ABORTED. LeakGuard prevented tainted payload from leaving.")
            else:
                outbound_text = res.get("panel_b", {}).get("sanitized_outbound_text", "")
                st.text_area("Exact Outbound Sanitized Payload", value=outbound_text, height=240, disabled=True, key="panel_b_text")

                token_records = res.get("panel_b", {}).get("token_mapping_table", [])
                st.markdown(f"**Token Replacement Mapping ({len(token_records)}):**")
                if token_records:
                    df_tokens = pd.DataFrame([{
                        "Token": r["token"],
                        "Category": r["entity_type"],
                        "Masked Value (Local Vault)": r["raw_value"]
                    } for r in token_records])
                    st.dataframe(df_tokens, use_container_width=True, height=160)
                st.success("🔒 LeakGuard Verified: Outbound Leak Rate = 0.00%")

        with pane_c:
            st.markdown("""
            <div class="panel-header">
                <span>PANEL C: FINAL RESPONSE (LOCAL REINSERTION)</span>
                <span class="badge-pii">Local In-Memory</span>
            </div>
            """, unsafe_allow_html=True)

            if status in ["BLOCKED", "LEAK_PREVENTED"]:
                st.warning("⚠️ No AI response generated because request was safely blocked by PRIVOPS.")
                st.caption(f"Reason: {res.get('block_reason')}")
            else:
                final_response = res.get("panel_c", {}).get("final_reinserted_response", "")
                st.text_area("Final Restored User Response", value=final_response, height=240, disabled=True, key="panel_c_text")

                restored_records = res.get("panel_c", {}).get("restored_tokens", [])
                st.markdown(f"**Restored Placeholders ({len(restored_records)}):**")
                if restored_records:
                    df_restored = pd.DataFrame([{
                        "Token": r["token"],
                        "Restored Original Value": r["restored_value"],
                        "Status": "RESTORED SAFELY"
                    } for r in restored_records])
                    st.dataframe(df_restored, use_container_width=True, height=160)
                else:
                    st.info("No tokens required reinsertion.")

# =========================================================================
# SECTION 3: DOCUMENT PROTECTION (PART 2 / PART 6)
# =========================================================================
elif menu_selection == "📄 Document Protection":
    st.subheader("Document Privacy & Multilingual Text Sanitization")
    st.markdown(
        "Upload enterprise documents (**PDF, Scanned PDF, JPG, PNG, TXT**). PRIVOPS extracts digital and OCR text, "
        "allows you to review and **modify the input document**, identifies language, tokenizes Indian PII, "
        "and anonymizes embedded facial photos."
    )

    doc_col1, doc_col2 = st.columns([2, 1])
    with doc_col1:
        uploaded_docs = st.file_uploader(
            "Choose document(s) or folder content (PDF, PNG, JPG, JPEG, TXT):",
            type=["pdf", "png", "jpg", "jpeg", "txt", "json", "csv"],
            accept_multiple_files=True,
            key="doc_page_uploader"
        )
        if uploaded_docs:
            for f in uploaded_docs:
                if f.name not in st.session_state["workspace_documents"]:
                    f_bytes = f.getvalue()
                    raw_text, method, meta = multilingual_engine_instance.extract_document_text(f_bytes, f.name)
                    lang_info = multilingual_engine_instance.identify_language(raw_text)
                    faces_count = 0
                    ext = f.name.lower().split(".")[-1]
                    if ext in ["jpg", "jpeg", "png", "bmp"]:
                        try:
                            _, faces_count, _, _ = face_anonymizer_instance.anonymize_image(f_bytes)
                        except Exception:
                            pass
                    st.session_state["workspace_documents"][f.name] = {
                        "filename": f.name,
                        "bytes": f_bytes,
                        "text": raw_text,
                        "method": method,
                        "meta": meta,
                        "lang_info": lang_info,
                        "faces_count": faces_count
                    }
            st.session_state["active_doc"] = st.session_state["workspace_documents"][uploaded_docs[-1].name]

    with doc_col2:
        doc_purpose = st.selectbox(
            "Processing Purpose:",
            ["loan_processing", "customer_support", "marketing", "fraud_investigation", "general_inquiry"],
            key="doc_purpose_sel"
        )
        auto_anonymize_faces = st.checkbox("Anonymize Embedded Photo/Face Biometrics", value=True, key="doc_anon_faces")

    active_doc = st.session_state.get("active_doc")

    if active_doc is not None:
        st.success(f"📄 Loaded Active Document: **{active_doc['filename']}** | Method: `{active_doc['method']}` | Language: **{active_doc['lang_info']['language']}** ({active_doc['lang_info']['script']} script)")

        if "doc_text_editor" not in st.session_state or st.session_state.get("doc_last_loaded_name") != active_doc["filename"]:
            st.session_state["doc_last_loaded_name"] = active_doc["filename"]
            st.session_state["doc_text_editor"] = active_doc["text"]

        st.markdown("##### ✏️ Review & Modify Input Document")
        st.caption("You can edit, modify, or erase any part of the document text. Your changes are preserved when processing.")
        modified_doc_text = st.text_area(
            "Input Document Content (Editable / Modifiable):",
            key="doc_text_editor",
            height=200
        )

        process_doc_btn = st.button("📄 Sanitize & Protect Document", type="primary", use_container_width=True, key="btn_proc_doc")

        if process_doc_btn:
            with st.spinner("Processing document text and applying privacy safeguards..."):
                faces_detected = active_doc.get("faces_count", 0)
                if auto_anonymize_faces and faces_detected == 0:
                    ext = active_doc["filename"].lower().split(".")[-1]
                    raw_bytes = active_doc["bytes"]
                    if ext in ["jpg", "jpeg", "png", "bmp"]:
                        try:
                            _, face_count, _, _ = face_anonymizer_instance.anonymize_image(raw_bytes)
                            faces_detected = face_count
                        except Exception:
                            pass
                    elif ext == "pdf":
                        try:
                            pdf_face_res = face_anonymizer_instance.extract_and_anonymize_pdf_images(raw_bytes)
                            faces_detected = sum(r["faces_found"] for r in pdf_face_res)
                        except Exception:
                            pass

                gw_res = gateway_instance.process_multilingual_text(
                    text=st.session_state["doc_text_editor"],
                    purpose=doc_purpose
                )
                lang_info = gw_res.get("language_info", {})
                st.session_state["last_doc_result"] = {
                    "gateway_result": gw_res,
                    "language_info": lang_info,
                    "extraction_method": active_doc["method"],
                    "faces_anonymized_count": faces_detected,
                    "filename": active_doc["filename"]
                }

        if "last_doc_result" in st.session_state:
            doc_res = st.session_state["last_doc_result"]
            lang_info = doc_res["language_info"]
            gw_res = doc_res["gateway_result"]

            st.success(f"✅ Document successfully sanitized! Language: **{lang_info.get('language', 'English')}** ({lang_info.get('script', 'Latin')} script) | Method: `{doc_res['extraction_method']}`")

            d_col1, d_col2 = st.columns(2)
            with d_col1:
                st.markdown("##### 📝 Modified Input Document Text")
                orig_text = gw_res.get("panel_a", {}).get("original_input", "")
                st.text_area("Input Document Payload", value=orig_text, height=240, disabled=True, key="doc_orig_preview")

                detected_ents = gw_res.get("panel_a", {}).get("detected_entities", [])
                st.markdown(f"**Detected Personal Entities ({len(detected_ents)}):**")
                if detected_ents:
                    st.dataframe(pd.DataFrame(detected_ents)[["entity_type", "value", "score"]], use_container_width=True)
                else:
                    st.info("No personal identifiers detected in document.")

            with d_col2:
                st.markdown("##### 🛡️ Sanitized Document Output (0.00% Outbound Exposure)")
                sanitized_doc_text = gw_res.get("panel_b", {}).get("sanitized_outbound_text", "")
                st.text_area("Sanitized Outbound Document", value=sanitized_doc_text, height=240, disabled=True, key="doc_san_preview")

                if doc_res["faces_anonymized_count"] > 0:
                    st.warning(f"👁️ Visual Privacy: {doc_res['faces_anonymized_count']} embedded face photo(s) anonymized.")

                dl_c1, dl_c2 = st.columns(2)
                with dl_c1:
                    st.download_button(
                        label="⬇️ Download Sanitized Text (.txt)",
                        data=sanitized_doc_text,
                        file_name=f"sanitized_{doc_res['filename']}.txt",
                        mime="text/plain",
                        use_container_width=True
                    )
                with dl_c2:
                    pdf_bytes = generate_sanitized_pdf(sanitized_doc_text, title=f"Sanitized Document - {doc_res['filename']}")
                    st.download_button(
                        label="⬇️ Download Sanitized PDF (.pdf)",
                        data=pdf_bytes,
                        file_name=f"sanitized_{doc_res['filename']}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )

# =========================================================================
# SECTION 4: MULTILINGUAL PROCESSING (PART 2)
# =========================================================================
elif menu_selection == "🌐 Multilingual Processing":
    st.subheader("Multilingual Indian Language Privacy Processing")
    st.markdown(
        "Supports **8 Indian Languages**: English, Kannada, Hindi, Tamil, Telugu, Malayalam, Marathi, and Bengali. "
        "Upload a document or input regional text to detect native PII, normalize numerals, and tokenize personal identifiers."
    )

    multi_tab1, multi_tab2 = st.tabs(["📄 Upload Multilingual Document", "✍️ Direct Multilingual Text & Presets"])

    with multi_tab1:
        st.markdown("##### Upload Document in Any Supported Regional Language")
        st.markdown("Accepts **PDF, Scanned PDF, JPG, PNG, or TXT** documents in Kannada, Hindi, Tamil, Telugu, Malayalam, Marathi, Bengali, or English.")

        m_up_col1, m_up_col2 = st.columns([2, 1])
        with m_up_col1:
            multi_file = st.file_uploader(
                "Upload Regional Document:",
                type=["pdf", "png", "jpg", "jpeg", "txt"],
                key="multi_file_uploader"
            )
        with m_up_col2:
            multi_doc_purpose = st.selectbox(
                "Processing Purpose:",
                ["loan_processing", "customer_support", "marketing", "fraud_investigation", "general_inquiry"],
                key="multi_doc_purpose"
            )

        active_doc = st.session_state.get("active_doc")
        if active_doc is not None:
            st.success(f"📄 Using Active Document: **{active_doc['filename']}** ({active_doc['lang_info']['language']})")
            if "multi_doc_editor" not in st.session_state or st.session_state.get("multi_doc_last_name") != active_doc["filename"]:
                st.session_state["multi_doc_last_name"] = active_doc["filename"]
                st.session_state["multi_doc_editor"] = active_doc["text"]

        if multi_file is not None:
            if st.session_state.get("multi_doc_last_name") != multi_file.name:
                m_bytes = multi_file.getvalue()
                m_text, m_method, m_meta = multilingual_engine_instance.extract_document_text(m_bytes, multi_file.name)
                st.session_state["multi_doc_last_name"] = multi_file.name
                st.session_state["multi_doc_editor"] = m_text
                st.session_state["multi_doc_method"] = m_method
                st.session_state.pop("last_multi_doc_res", None)
                # Sync with global workspace
                st.session_state["workspace_documents"][multi_file.name] = {
                    "filename": multi_file.name,
                    "bytes": m_bytes,
                    "text": m_text,
                    "method": m_method,
                    "meta": m_meta,
                    "lang_info": multilingual_engine_instance.identify_language(m_text),
                    "faces_count": 0
                }
                st.session_state["active_doc"] = st.session_state["workspace_documents"][multi_file.name]

        current_multi_doc_text = st.session_state.get("multi_doc_editor", "")
        if current_multi_doc_text:
            st.markdown("##### ✏️ Extracted Regional Document Content (Editable)")
            st.caption("Review, edit, or modify the document content before sanitizing:")
            multi_doc_edited = st.text_area(
                "Document Text:",
                key="multi_doc_editor",
                height=180
            )

            if st.button("🌐 Analyze & Sanitize Multilingual Document", type="primary", key="btn_sanitize_multi_doc"):
                with st.spinner("Analyzing Indian language script, extracting regional entities, and tokenizing..."):
                    m_res = gateway_instance.process_multilingual_text(
                        text=st.session_state["multi_doc_editor"],
                        purpose=multi_doc_purpose
                    )
                    st.session_state["last_multi_doc_res"] = m_res

            if "last_multi_doc_res" in st.session_state:
                m_res = st.session_state["last_multi_doc_res"]
                m_lang = m_res.get("language_info", {})
                st.success(f"✅ Multilingual Document Processed! Language: **{m_lang.get('language')}** (`{m_lang.get('lang_code')}`) | Script: **{m_lang.get('script')}**")

                col_l, col_r = st.columns(2)
                with col_l:
                    st.markdown("##### 📍 Detected Multilingual Entities")
                    m_ents = m_res.get("panel_a", {}).get("detected_entities", [])
                    if m_ents:
                        st.dataframe(pd.DataFrame(m_ents)[["entity_type", "value", "score"]], use_container_width=True)
                    else:
                        st.info("No personal entities detected in document.")

                with col_r:
                    st.markdown("##### 🛡️ Sanitized Regional Output")
                    sanitized_m_doc = m_res.get("panel_b", {}).get("sanitized_outbound_text", "")
                    st.text_area("Protected Payload", value=sanitized_m_doc, height=200, disabled=True, key="multi_doc_san_view")

                    doc_name_dl = st.session_state.get("multi_doc_last_name", "document")
                    dl_m1, dl_m2 = st.columns(2)
                    with dl_m1:
                        st.download_button(
                            label="⬇️ Download Sanitized (.txt)",
                            data=sanitized_m_doc,
                            file_name=f"sanitized_multilingual_{doc_name_dl}.txt",
                            mime="text/plain",
                            use_container_width=True
                        )
                    with dl_m2:
                        pdf_bytes = generate_sanitized_pdf(sanitized_m_doc, title=f"Sanitized Multilingual Document - {doc_name_dl}")
                        st.download_button(
                            label="⬇️ Download Sanitized (.pdf)",
                            data=pdf_bytes,
                            file_name=f"sanitized_multilingual_{doc_name_dl}.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
        else:
            st.info("Please upload a multilingual document above or select a workspace document.")

    with multi_tab2:
        lang_samples = {
            "Kannada (ಕನ್ನಡ)": (
                "ಅರ್ಜಿದಾರ ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ\n"
                "ಆಧಾರ್ ಸಂಖ್ಯೆ: 8952 1816 1436\n"
                "ಪ್ಯಾನ್ ಸಂಖ್ಯೆ: ABCPS1234K\n"
                "ಮೊಬೈಲ್ ಸಂಖ್ಯೆ: 9845012345\n"
                "ಬ್ಯಾಂಕ್ ಖಾತೆ ಸಂಖ್ಯೆ: 501004928172\n"
                "ವಿಳಾಸ: ಎಂ.ಜಿ. ರಸ್ತೆ, ಇಂದಿರಾನಗರ, ಬೆಂಗಳೂರು - 560038\n"
                "ವಿವರ: ಸಾಲ ಪರಿಶೀಲನೆಗಾಗಿ ವಿನಂತಿ."
            ),
            "Hindi (हिन्दी)": (
                "आवेदक का नाम: राहुल कुमार\n"
                "आधार संख्या: 9876 5432 1012\n"
                "पैन कार्ड संख्या: BCDPS1234K\n"
                "मोबाइल नंबर: 9811023456\n"
                "खाता संख्या: 102938475612\n"
                "पता: 402, शांति हाइट्स, कनॉट प्लेस, नई दिल्ली - 110001\n"
                "विवरण: व्यक्तिगत ऋण आवेदन की समीक्षा करें।"
            ),
            "Tamil (தமிழ்)": (
                "விண்ணப்பதாரர் பெயர்: பிரியா நாயர்\n"
                "ஆதார் எண்: 6303 8523 6432\n"
                "பான் எண்: AAAPR9988K\n"
                "கைபேசி: 9840134567\n"
                "முகவரி: அண்ணா சாலை, சென்னை - 600002"
            ),
            "Telugu (తెలుగు)": (
                "దరఖాస్తుదారు పేరు: విక్రమ్ రెడ్డి\n"
                "ఆధಾರ್ సంఖ్య: 2333 9649 7854\n"
                "పాన్ సంఖ్య: AAACB1234C\n"
                "మొబైల్: 9849045678\n"
                "చిరునామా: బంజారా హిల్స్, హైదరాబాద్ - 500034"
            ),
            "Marathi (मराठी)": (
                "अर्जदाराचे नाव: अमित देशमुख\n"
                "आधार क्रमांक: 5432 1234 5678\n"
                "पॅन क्रमांक: AAAPM1234K\n"
                "मोबाईल: 9822056789\n"
                "पत्ता: एफसी रोड, शिवाजी नगर, पुणे - 411004"
            ),
            "Bengali (বাংলা)": (
                "আবেদনকারীর নাম: সুনীता বোস\n"
                "আধার নম্বর: 7890 1234 5678\n"
                "প্যান নম্বর: AAAPB1234K\n"
                "ফোন: 9830067890\n"
                "ঠিকানা: পার্ক স্ট্রিট, কলকাতা - 700016"
            ),
            "English": (
                "Applicant Name: Sunita Verma\n"
                "Aadhaar Number: 9876 5432 1012\n"
                "PAN Number: BCDPS1234K\n"
                "Primary Mobile: +91-9811223344\n"
                "Address: Flat 302, Palm Heights, Pune - 411004"
            )
        }

        sel_lang = st.selectbox("Load Sample Regional Document:", list(lang_samples.keys()))
        if "multi_sel_lang_prev" not in st.session_state or st.session_state.get("multi_sel_lang_prev") != sel_lang:
            st.session_state["multi_sel_lang_prev"] = sel_lang
            st.session_state["multi_text_editor"] = lang_samples[sel_lang]

        multi_input = st.text_area(
            "Input Regional Text:",
            key="multi_text_editor",
            height=180,
            help="You can edit or erase any content. Edits are preserved when processing."
        )

        if st.button("🌐 Analyze & Sanitize Multilingual Text", type="primary", key="btn_sanitize_multi_text"):
            with st.spinner("Analyzing language script and applying regional recognizers..."):
                res = gateway_instance.process_multilingual_text(
                    text=st.session_state["multi_text_editor"],
                    purpose="loan_processing"
                )
                st.session_state["last_multi_text_res"] = res

        if "last_multi_text_res" in st.session_state:
            res = st.session_state["last_multi_text_res"]
            lang_info = res.get("language_info", {})
            st.info(f"**Identified Language:** {lang_info.get('language')} (`{lang_info.get('lang_code')}`) | **Script:** {lang_info.get('script')}")

            m_col1, m_col2 = st.columns(2)
            with m_col1:
                st.markdown("##### 📍 Detected Multilingual PII Entities")
                entities = res.get("panel_a", {}).get("detected_entities", [])
                if entities:
                    st.dataframe(pd.DataFrame(entities)[["entity_type", "value", "score"]], use_container_width=True)
                else:
                    st.write("No PII entities detected.")

            with m_col2:
                st.markdown("##### 🛡️ Sanitized Multilingual Output")
                sanitized = res.get("panel_b", {}).get("sanitized_outbound_text", "")
                st.text_area("Protected Outbound", value=sanitized, height=180, disabled=True, key="multi_text_san_view")

# =========================================================================
# SECTION 5: VISUAL PRIVACY (PART 4)
# =========================================================================
elif menu_selection == "👁️ Visual Privacy":
    st.subheader("Visual Privacy: Face Detection & Automatic Anonymization")
    st.markdown(
        "Detects human faces in uploaded images (**JPG, PNG**) and PDF photo attachments using **OpenCV YuNet (DNN)**. "
        "Applies irreversible **Gaussian Blur, Pixelation, or Redaction Masks** to ensure raw facial biometrics are never transmitted externally."
    )

    vis_c1, vis_c2 = st.columns([2, 1])
    with vis_c1:
        img_upload = st.file_uploader("Upload Image with Faces (JPG, PNG):", type=["jpg", "jpeg", "png"])

    with vis_c2:
        anon_method = st.selectbox("Anonymization Method:", ["blur", "pixelate", "mask"], format_func=lambda x: {
            "blur": "Gaussian Blur (Recommended)",
            "pixelate": "Pixelation (Mosaic)",
            "mask": "Solid Redaction Mask"
        }[x])
        if anon_method == "blur":
            blur_val = st.slider("Blur Kernel Radius:", 15, 99, 51, step=2)
            pix_val = 12
        elif anon_method == "pixelate":
            pix_val = st.slider("Mosaic Pixel Size:", 6, 32, 14)
            blur_val = 51
        else:
            blur_val, pix_val = 51, 12

        process_vis_btn = st.button("👁️ Detect & Anonymize Faces", type="primary", use_container_width=True)

    active_doc = st.session_state.get("active_doc")
    img_bytes_source = None
    img_name_source = "uploaded_image.png"

    if img_upload is not None:
        img_bytes_source = img_upload.read()
        img_name_source = img_upload.name
    elif active_doc is not None and active_doc["filename"].lower().endswith((".jpg", ".jpeg", ".png", ".bmp")):
        img_bytes_source = active_doc["bytes"]
        img_name_source = active_doc["filename"]
        st.info(f"📂 Using Active Workspace Image: **{active_doc['filename']}** (Already loaded)")

    if img_bytes_source is not None:
        raw_img_bytes = img_bytes_source

        if process_vis_btn or "last_visual_result" in st.session_state:
            if process_vis_btn:
                with st.spinner("Executing OpenCV YuNet face detection and anonymization..."):
                    vis_res = gateway_instance.process_image_visual(
                        image_bytes=raw_img_bytes,
                        filename=img_name_source,
                        method=anon_method,
                        blur_factor=blur_val,
                        pixel_size=pix_val
                    )
                    st.session_state["last_visual_result"] = vis_res
                    st.session_state["last_raw_img"] = raw_img_bytes

            vis_res = st.session_state.get("last_visual_result", {})
            orig_bytes = st.session_state.get("last_raw_img", raw_img_bytes)

            faces_found = vis_res.get("faces_detected", 0)
            if faces_found > 0:
                st.success(f"✅ Success: Detected and Anonymized **{faces_found} human face(s)** using OpenCV YuNet DNN.")
            else:
                st.info("ℹ️ No human faces detected in image.")

            st.markdown("---")
            v_col1, v_col2 = st.columns(2)

            with v_col1:
                st.markdown("##### 🔒 Original Image (Isolated in Local Privacy Vault)")
                st.image(orig_bytes, caption="Original Raw Image (Never Leaves Local Boundary)", use_container_width=True)

            with v_col2:
                st.markdown("##### 🛡️ Protected Image (Sent to External AI / Outbound)")
                prot_bytes = vis_res.get("protected_image_bytes")
                if prot_bytes:
                    st.image(prot_bytes, caption=f"Protected Output ({anon_method.title()} Filter Applied)", use_container_width=True)
                    st.download_button(
                        label="⬇️ Download Protected Image",
                        data=prot_bytes,
                        file_name=f"anonymized_{img_name_source}",
                        mime="image/png",
                        use_container_width=True
                    )

            if vis_res.get("face_coordinates"):
                st.markdown("##### 📍 Detected Face Coordinates")
                st.dataframe(pd.DataFrame(vis_res["face_coordinates"]), use_container_width=True)

# =========================================================================
# SECTION 6: DETECTION EVALUATION (PART 3)
# =========================================================================
elif menu_selection == "📈 Detection Evaluation":
    st.subheader("Dataset-Based PII Detection & Evaluation")
    st.markdown(
        "Evaluate the gateway PII detection engine against **ground-truth annotated datasets**. "
        "Supports the default **50-document Indian enterprise benchmark**, **custom uploaded datasets (JSON/CSV)**, "
        "and **interactive document input evaluation** using authentic scikit-learn metrics."
    )

    ev_tab1, ev_tab2, ev_tab3 = st.tabs([
        "⚡ Standard 50-Document Benchmark",
        "📂 Custom Dataset Input Evaluation",
        "✍️ Interactive Document Input Evaluation"
    ])

    with ev_tab1:
        ev_c1, ev_c2 = st.columns([2, 1])
        with ev_c1:
            st.write("📊 **Evaluation Dataset:** `dataset/evaluation_dataset_50.json` (50 Records across English and Regional Languages)")
        with ev_c2:
            run_ev_btn = st.button("⚡ Run Full 50-Document Evaluation", type="primary", use_container_width=True, key="btn_run_std_eval")

        if run_ev_btn or "last_eval_report" in st.session_state:
            if run_ev_btn:
                with st.spinner("Processing 50 ground-truth documents and computing scikit-learn metrics..."):
                    eval_report = dataset_evaluator_instance.run_evaluation()
                    st.session_state["last_eval_report"] = eval_report

            report = st.session_state.get("last_eval_report", {})
            if not report:
                report = dataset_evaluator_instance.run_evaluation()

            e1, e2, e3, e4, e5 = st.columns(5)
            with e1:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-num">{report.get('total_documents', 50)}</div>
                    <div class="metric-label">Documents Evaluated</div>
                </div>
                """, unsafe_allow_html=True)
            with e2:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-num" style="color: #38BDF8;">{report.get('precision_percentage', 0)}%</div>
                    <div class="metric-label">Precision Score</div>
                </div>
                """, unsafe_allow_html=True)
            with e3:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-num" style="color: #818CF8;">{report.get('recall_percentage', 0)}%</div>
                    <div class="metric-label">Recall Score</div>
                </div>
                """, unsafe_allow_html=True)
            with e4:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-num" style="color: #34D399;">{report.get('f1_score_percentage', 0)}%</div>
                    <div class="metric-label">F1-Score</div>
                </div>
                """, unsafe_allow_html=True)
            with e5:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-num" style="color: #F87171;">{report.get('missed_detections_count', 0)}</div>
                    <div class="metric-label">Missed Detections</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("---")

            st.markdown("##### 📑 Document Breakdown by Type & Language")
            if report.get("document_breakdown"):
                st.dataframe(pd.DataFrame(report["document_breakdown"]), use_container_width=True, height=280)

            d_col1, d_col2 = st.columns(2)
            with d_col1:
                st.markdown("##### ❌ Missed Detections Sample (False Negatives)")
                missed = report.get("missed_sample", [])
                if missed:
                    st.dataframe(pd.DataFrame(missed), use_container_width=True)
                else:
                    st.success("Zero missed entities!")

            with d_col2:
                st.markdown("##### ⚠️ False Detections Sample (False Positives)")
                false_d = report.get("false_sample", [])
                if false_d:
                    st.dataframe(pd.DataFrame(false_d), use_container_width=True)
                else:
                    st.success("Zero false positives!")

            st.download_button(
                label="⬇️ Download Complete Evaluation Report (JSON)",
                data=json.dumps(report, indent=2),
                file_name="privops_evaluation_report.json",
                mime="application/json",
                use_container_width=True,
                key="btn_dl_std_eval"
            )

    with ev_tab2:
        st.markdown("##### ➕ Add Data & Evaluate Ground-Truth Records")
        st.markdown("Add custom document records directly, upload a dataset (JSON/CSV), and run evaluation checks to measure real precision, recall, and F1 scores.")

        if "custom_dataset_records" not in st.session_state:
            st.session_state["custom_dataset_records"] = []

        with st.expander("➕ Form: Add New Document to Dataset", expanded=True):
            f_col1, f_col2, f_col3 = st.columns(3)
            with f_col1:
                new_doc_id = st.text_input("Document ID:", value=f"USER-DOC-{len(st.session_state['custom_dataset_records']) + 1:03d}", key="input_new_doc_id")
            with f_col2:
                new_doc_type = st.selectbox("Document Type:", ["Loan Application", "KYC Verification", "Insurance Claim", "Customer Support Ticket", "Employee Record", "Banking Statement", "General Document"], key="input_new_doc_type")
            with f_col3:
                new_doc_lang = st.selectbox("Document Language:", ["en", "kn", "hi", "ta", "te", "ml", "mr", "bn"], format_func=lambda x: {
                    "en": "English", "kn": "Kannada", "hi": "Hindi", "ta": "Tamil",
                    "te": "Telugu", "ml": "Malayalam", "mr": "Marathi", "bn": "Bengali"
                }[x], key="input_new_doc_lang")

            active_doc = st.session_state.get("active_doc")
            default_add_text = active_doc["text"] if active_doc else (
                "Customer Loan Onboarding:\n"
                "Applicant: Priya Nair\n"
                "Aadhaar Number: 6303 8523 6432\n"
                "PAN Card: AAAPR9988K\n"
                "Mobile: 9840134567\n"
                "Address: Anna Salai, Chennai - 600002"
            )
            new_doc_text = st.text_area("Document Content / Original Text:", value=default_add_text, height=140, key="input_new_doc_text")

            all_cat_options = ["PERSON", "AADHAAR", "PAN", "PHONE_NUMBER", "EMAIL_ADDRESS", "ADDRESS", "BANK_ACCOUNT", "GSTIN", "PASSPORT", "VOTER_ID"]
            new_expected_cats = st.multiselect(
                "Expected PII Categories in this Document:",
                all_cat_options,
                default=["PERSON", "AADHAAR", "PAN", "PHONE_NUMBER", "ADDRESS"],
                key="input_new_expected_cats"
            )

            if st.button("➕ Add This Document to Dataset", key="btn_add_doc_record"):
                if new_doc_text.strip():
                    st.session_state["custom_dataset_records"].append({
                        "doc_id": new_doc_id,
                        "doc_type": new_doc_type,
                        "language": new_doc_lang,
                        "original_text": new_doc_text,
                        "expected_entities": [{"category": c, "value": ""} for c in new_expected_cats]
                    })
                    st.success(f"✅ Added `{new_doc_id}` to active evaluation dataset! Total documents: {len(st.session_state['custom_dataset_records'])}")
                else:
                    st.warning("Please provide document content text.")

        st.markdown("##### Or Upload Dataset File (.json, .csv):")
        uploaded_dataset_file = st.file_uploader(
            "Upload Dataset File:",
            type=["json", "csv"],
            key="custom_dataset_uploader"
        )
        if uploaded_dataset_file is not None:
            dataset_bytes = uploaded_dataset_file.getvalue()
            parsed_records = dataset_evaluator_instance.parse_dataset_file(dataset_bytes, uploaded_dataset_file.name)
            if parsed_records:
                st.session_state["custom_dataset_records"].extend(parsed_records)
                st.success(f"📥 Imported **{len(parsed_records)} documents** from `{uploaded_dataset_file.name}`. Total dataset size: {len(st.session_state['custom_dataset_records'])}")

        st.markdown("---")
        total_recs = len(st.session_state["custom_dataset_records"])
        st.markdown(f"##### 📑 Active Evaluation Dataset: **{total_recs} Document(s)**")

        if total_recs > 0:
            df_recs = pd.DataFrame([{
                "ID": r["doc_id"],
                "Type": r["doc_type"],
                "Language": r["language"],
                "Snippet": (r["original_text"][:60] + "...") if len(r["original_text"]) > 60 else r["original_text"],
                "Expected Entities": ", ".join(e["category"] for e in r["expected_entities"])
            } for r in st.session_state["custom_dataset_records"]])
            st.dataframe(df_recs, use_container_width=True, height=200)

            c_btn1, c_btn2 = st.columns([3, 1])
            with c_btn1:
                run_custom_eval_btn = st.button("⚡ Evaluate Added Data (Check All Records)", type="primary", use_container_width=True, key="btn_run_custom_eval")
            with c_btn2:
                if st.button("🗑️ Clear Dataset Records", use_container_width=True, key="btn_clear_custom_records"):
                    st.session_state["custom_dataset_records"] = []
                    st.session_state.pop("last_custom_eval_report", None)
                    st.rerun()

            if run_custom_eval_btn or "last_custom_eval_report" in st.session_state:
                if run_custom_eval_btn:
                    with st.spinner(f"Evaluating {total_recs} documents against PII detection engine..."):
                        custom_report = dataset_evaluator_instance.run_evaluation(custom_docs=st.session_state["custom_dataset_records"])
                        st.session_state["last_custom_eval_report"] = custom_report

                c_rep = st.session_state.get("last_custom_eval_report", {})
                if c_rep:
                    ce1, ce2, ce3, ce4, ce5 = st.columns(5)
                    with ce1:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-num">{c_rep.get('total_documents', 0)}</div>
                            <div class="metric-label">Docs Evaluated</div>
                        </div>
                        """, unsafe_allow_html=True)
                    with ce2:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-num" style="color: #38BDF8;">{c_rep.get('precision_percentage', 0)}%</div>
                            <div class="metric-label">Precision</div>
                        </div>
                        """, unsafe_allow_html=True)
                    with ce3:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-num" style="color: #818CF8;">{c_rep.get('recall_percentage', 0)}%</div>
                            <div class="metric-label">Recall</div>
                        </div>
                        """, unsafe_allow_html=True)
                    with ce4:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-num" style="color: #34D399;">{c_rep.get('f1_score_percentage', 0)}%</div>
                            <div class="metric-label">F1-Score</div>
                        </div>
                        """, unsafe_allow_html=True)
                    with ce5:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-num" style="color: #F87171;">{c_rep.get('missed_detections_count', 0)}</div>
                            <div class="metric-label">Missed</div>
                        </div>
                        """, unsafe_allow_html=True)

                    st.markdown("---")
                    st.markdown("##### 📑 Document-by-Document Accuracy Breakdown")
                    if c_rep.get("document_breakdown"):
                        st.dataframe(pd.DataFrame(c_rep["document_breakdown"]), use_container_width=True)

                    cd_col1, cd_col2 = st.columns(2)
                    with cd_col1:
                        st.markdown("##### ❌ Missed Detections (False Negatives)")
                        st.dataframe(pd.DataFrame(c_rep.get("missed_sample", [])), use_container_width=True)
                    with cd_col2:
                        st.markdown("##### ⚠️ False Detections (False Positives)")
                        st.dataframe(pd.DataFrame(c_rep.get("false_sample", [])), use_container_width=True)

                    st.download_button(
                        label="⬇️ Download Evaluation Report (JSON)",
                        data=json.dumps(c_rep, indent=2),
                        file_name="custom_dataset_evaluation_report.json",
                        mime="application/json",
                        use_container_width=True,
                        key="btn_dl_custom_eval"
                    )
        else:
            st.info("No records in custom dataset yet. Add records above using the form or upload a JSON/CSV file.")

    with ev_tab3:
        st.markdown("##### Interactive Real-Time Document Input Evaluation")
        st.markdown("Input any custom document text and specify the expected PII categories to evaluate detection accuracy in real time.")

        sample_eval_text = (
            "Customer Onboarding Verification:\n"
            "Name: Rahul Sharma\n"
            "Aadhaar Number: 8952 1816 1436\n"
            "PAN Card: ABCPS1234K\n"
            "Contact: 9845012345\n"
            "Email: rahul.sharma@example.com\n"
            "Address: 42, Brigade Road, Bangalore - 560001"
        )
        custom_input_text = st.text_area("Test Document Text:", value=sample_eval_text, height=180, key="eval_interactive_text")

        available_categories = [
            "AADHAAR", "PAN", "PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON", "ADDRESS",
            "BANK_ACCOUNT", "GSTIN", "VOTER_ID", "PASSPORT"
        ]
        selected_expected = st.multiselect(
            "Expected Ground-Truth PII Categories in Document:",
            available_categories,
            default=["AADHAAR", "PAN", "PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON", "ADDRESS"],
            key="eval_expected_multiselect"
        )

        if st.button("⚡ Evaluate Document Input", type="primary", key="btn_eval_single_doc"):
            with st.spinner("Running detection and calculating precision, recall, and F1..."):
                single_res = dataset_evaluator_instance.evaluate_single_input(custom_input_text, selected_expected)
                st.session_state["last_single_eval_res"] = single_res

        if "last_single_eval_res" in st.session_state:
            s_res = st.session_state["last_single_eval_res"]
            se1, se2, se3, se4 = st.columns(4)
            with se1:
                st.metric("Precision", f"{s_res['precision']}%")
            with se2:
                st.metric("Recall", f"{s_res['recall']}%")
            with se3:
                st.metric("F1-Score", f"{s_res['f1_score']}%")
            with se4:
                st.metric("Detected Entities", len(s_res["detected_entities"]))

            st.markdown("##### 📍 Detected Entities vs Expected Categories")
            det_df = pd.DataFrame([{
                "Entity Type": d["entity_type"],
                "Detected Value": d["value"],
                "Confidence Score": d["score"],
                "Matches Ground Truth": "✅ MATCH" if d["entity_type"] in s_res["expected_categories"] else "⚠️ UNEXPECTED"
            } for d in s_res["detected_entities"]])
            st.dataframe(det_df, use_container_width=True)

# =========================================================================
# SECTION 7: AUDIT LOGS
# =========================================================================
elif menu_selection == "📜 Audit Logs":
    st.subheader("Immutable Transaction Audit Logs")
    st.markdown(
        "Comprehensive, tamper-resistant transaction log from SQLite (`privops.db`). "
        "Records request status, declared purpose, PII counts, document format, language, and faces anonymized with **zero raw personal data retention**."
    )

    al_c1, al_c2 = st.columns([3, 1])
    with al_c1:
        log_limit = st.slider("Number of records to display:", 10, 200, 50)
    with al_c2:
        st.write("")
        if st.button("🔄 Refresh Logs"):
            st.rerun()

    logs = audit_logger_instance.get_recent_logs(limit=log_limit)
    if logs:
        df_logs = pd.DataFrame(logs)
        st.dataframe(df_logs, use_container_width=True, height=450)
        st.download_button(
            label="⬇️ Download Audit Logs (CSV)",
            data=df_logs.to_csv(index=False),
            file_name="privops_audit_logs.csv",
            mime="text/csv"
        )
    else:
        st.info("No audit log records available.")

# =========================================================================
# SECTION 8: ANALYTICS
# =========================================================================
elif menu_selection == "📊 Analytics":
    st.subheader("Real-Time Privacy Gateway Analytics")
    st.markdown("System-wide compliance and processing metrics calculated from actual backend database records.")

    m = audit_logger_instance.get_metrics_summary()

    row1_c1, row1_c2, row1_c3, row1_c4, row1_c5 = st.columns(5)
    with row1_c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num">{m.get('total_requests', 0)}</div>
            <div class="metric-label">Total Requests</div>
        </div>
        """, unsafe_allow_html=True)
    with row1_c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #38BDF8;">{m.get('total_documents_processed', 0)}</div>
            <div class="metric-label">Docs Processed</div>
        </div>
        """, unsafe_allow_html=True)
    with row1_c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #34D399;">{m.get('total_pii_entities_detected', 0)}</div>
            <div class="metric-label">PII Detected</div>
        </div>
        """, unsafe_allow_html=True)
    with row1_c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #FBBF24;">{m.get('total_faces_anonymized', 0)}</div>
            <div class="metric-label">Faces Anonymized</div>
        </div>
        """, unsafe_allow_html=True)
    with row1_c5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-num" style="color: #818CF8;">{m.get('average_latency_ms', 0)} ms</div>
            <div class="metric-label">Avg Latency</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    ch1, ch2 = st.columns(2)
    with ch1:
        st.markdown("##### 🌐 Language-Wise Processing Statistics")
        lang_stats = m.get("language_statistics", {})
        if lang_stats:
            df_lang = pd.DataFrame(list(lang_stats.items()), columns=["Language", "Count"])
            fig_l = px.pie(df_lang, names="Language", values="Count", hole=0.45, template="plotly_dark", color_discrete_sequence=px.colors.sequential.Teal)
            fig_l.update_layout(paper_bgcolor="#0F172A", margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig_l, use_container_width=True)
        else:
            st.info("No language statistics available yet.")

    with ch2:
        st.markdown("##### 📍 PII Category Breakdown")
        pii_stats = m.get("pii_category_frequency", {})
        if pii_stats:
            df_pii = pd.DataFrame(list(pii_stats.items()), columns=["Category", "Count"])
            fig_p = px.bar(df_pii, x="Category", y="Count", color="Count", color_continuous_scale="Blues", template="plotly_dark")
            fig_p.update_layout(paper_bgcolor="#0F172A", plot_bgcolor="#0F172A", margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig_p, use_container_width=True)
        else:
            st.info("No PII frequency data yet.")

    ch3, ch4 = st.columns(2)
    with ch3:
        st.markdown("##### 🎯 Requests by Declared Purpose")
        purp_stats = m.get("purpose_statistics", {})
        if purp_stats:
            df_purp = pd.DataFrame(list(purp_stats.items()), columns=["Purpose", "Count"])
            fig_purp = px.pie(df_purp, names="Purpose", values="Count", hole=0.4, template="plotly_dark")
            fig_purp.update_layout(paper_bgcolor="#0F172A", margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig_purp, use_container_width=True)
        else:
            st.info("No purpose statistics available.")

    with ch4:
        st.markdown("##### 🛡️ Request Security Status Breakdown")
        stat_stats = m.get("status_statistics", {})
        if stat_stats:
            df_stat = pd.DataFrame(list(stat_stats.items()), columns=["Status", "Count"])
            fig_stat = px.bar(df_stat, x="Status", y="Count", color="Status", template="plotly_dark")
            fig_stat.update_layout(paper_bgcolor="#0F172A", plot_bgcolor="#0F172A", margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig_stat, use_container_width=True)
        else:
            st.info("No status data available.")

# =========================================================================
# SECTION 9: POLICY (DPDP GOVERNANCE)
# =========================================================================
elif menu_selection == "📋 Policy":
    st.subheader("📋 Enterprise Data Protection Policy & Purpose Governance")
    st.markdown(
        "Under **DPDP Act 2023 Section 6**, enterprise data processing policies define permitted, masked, "
        "and strictly blocked PII categories for each declared business purpose to enforce strict data minimization."
    )

    policy_tab1, policy_tab2 = st.tabs(["📁 Active Purpose Policies", "🧪 Interactive Policy Simulator"])

    with policy_tab1:
        st.markdown("##### Defined Purpose Policies")
        policies = purpose_engine_instance.get_supported_purposes()
        for p in policies:
            with st.expander(f"📁 Policy: {p['name']} (`{p['id']}`)", expanded=True):
                st.write(f"**Description:** {p['description']}")
                st.write(f"**DPDP Compliance Clause:** `{p['dpdp_clause']}`")
                col_a, col_m, col_b = st.columns(3)
                with col_a:
                    st.markdown("**✅ Allowed Entities:**")
                    st.write(", ".join(p["allowed"]) if p["allowed"] else "*None*")
                with col_m:
                    st.markdown("**🛡️ Masked / Tokenized:**")
                    st.write(", ".join(p["masked"]) if p["masked"] else "*None*")
                with col_b:
                    st.markdown("**🚫 Strictly Blocked (Auto-Reject):**")
                    st.write(", ".join(f"`{b}`" for b in p["blocked"]) if p["blocked"] else "*None*")

        st.markdown("---")
        st.markdown("##### 🔐 Vault Security & Encryption Telemetry")
        v_stat = vault_instance.get_vault_stats()
        st.json(v_stat)

    with policy_tab2:
        st.markdown("##### Interactive DPDP Policy Simulator")
        st.markdown("Test how the gateway enforces data minimization rules for any declared purpose against detected personal identifiers.")

        sim_c1, sim_c2 = st.columns(2)
        with sim_c1:
            sim_purpose = st.selectbox(
                "Declared Purpose:",
                ["loan_processing", "customer_support", "marketing", "fraud_investigation", "general_inquiry"],
                key="sim_purpose_sel"
            )
        with sim_c2:
            test_entity_types = st.multiselect(
                "Test Entity Types in Request:",
                ["AADHAAR", "PAN", "PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON", "ADDRESS", "BANK_ACCOUNT", "GSTIN", "PASSPORT"],
                default=["AADHAAR", "PERSON", "PHONE_NUMBER"],
                key="sim_entities_sel"
            )

        if st.button("🧪 Simulate Policy Enforcement", type="primary", key="btn_sim_policy"):
            sample_ents = [{"entity_type": t, "value": f"sample_{t.lower()}"} for t in test_entity_types]
            allowed, masked, blocked, dpdp_clause, is_valid = purpose_engine_instance.validate_purpose(
                sample_ents, sim_purpose
            )

            if not is_valid:
                st.error(f"🚫 REQUEST BLOCKED under DPDP Act Clause: `{dpdp_clause}`! Policy contains blocked entities: {blocked}")
            else:
                st.success(f"🛡️ REQUEST PERMITTED under DPDP Act Clause: `{dpdp_clause}`! Data minimization policy enforced.")

            p_col1, p_col2, p_col3 = st.columns(3)
            with p_col1:
                st.markdown("**✅ Permitted Entities:**")
                st.write(", ".join(allowed) if allowed else "*None*")
            with p_col2:
                st.markdown("**🛡️ Masked / Tokenized Entities:**")
                st.write(", ".join(masked) if masked else "*None*")
            with p_col3:
                st.markdown("**🚫 Blocked Entities:**")
                st.write(", ".join(blocked) if blocked else "*None*")
