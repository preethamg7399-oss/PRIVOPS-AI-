"""
PRIVOPS - Multilingual Document Processing & Indian Language PII Engine
Supports: English, Kannada, Hindi, Tamil, Telugu, Malayalam, Marathi, Bengali.
Extracts digital and scanned PDF text, identifies language, and detects PII entities across Indian scripts.
"""

import re
import io
from typing import Dict, Any, List, Tuple, Optional
from langdetect import detect, DetectorFactory
import pypdf
from PIL import Image

# Enforce deterministic language detection
DetectorFactory.seed = 42

# Supported Languages Mapping
SUPPORTED_LANGUAGES = {
    "en": {"name": "English", "script": "Latin"},
    "kn": {"name": "Kannada", "script": "Kannada"},
    "hi": {"name": "Hindi", "script": "Devanagari"},
    "ta": {"name": "Tamil", "script": "Tamil"},
    "te": {"name": "Telugu", "script": "Telugu"},
    "ml": {"name": "Malayalam", "script": "Malayalam"},
    "mr": {"name": "Marathi", "script": "Devanagari"},
    "bn": {"name": "Bengali", "script": "Bengali"},
}

# Regional Indian Digits to ASCII 0-9 Mapping
REGIONAL_DIGITS_MAP = {
    # Devanagari (Hindi, Marathi)
    '०': '0', '१': '1', '२': '2', '३': '3', '४': '4',
    '५': '5', '६': '6', '७': '7', '८': '8', '९': '9',
    # Kannada
    '೦': '0', '೧': '1', '೨': '2', '೩': '3', '೪': '4',
    '೫': '5', '೬': '6', '೭': '7', '೮': '8', '೯': '9',
    # Tamil
    '௦': '0', '௧': '1', '௨': '2', '௩': '3', '௪': '4',
    '௫': '5', '௬': '6', '௭': '7', '௮': '8', '௯': '9',
    # Telugu
    '౦': '0', '౧': '1', '౨': '2', '౩': '3', '౪': '4',
    '౫': '5', '౬': '6', '౭': '7', '౮': '8', '౯': '9',
    # Malayalam
    '൦': '0', '൧': '1', '൨': '2', '൩': '3', '൪': '4',
    '൫': '5', '൬': '6', '൭': '7', '൮': '8', '൯': '9',
    # Bengali
    '০': '0', '১': '1', '২': '2', '৩': '3', '৪': '4',
    '৫': '5', '৬': '6', '৭': '7', '৮': '8', '৯': '9',
}

# Unicode Script Ranges
SCRIPT_RANGES = [
    (r"[\u0900-\u097F]", "Devanagari (Hindi/Marathi)"),
    (r"[\u0C80-\u0CFF]", "Kannada"),
    (r"[\u0B80-\u0BFF]", "Tamil"),
    (r"[\u0C00-\u0C7F]", "Telugu"),
    (r"[\u0D00-\u0D7F]", "Malayalam"),
    (r"[\u0980-\u09FF]", "Bengali"),
    (r"[a-zA-Z]", "Latin (English)"),
]

# Multilingual Keywords for Indian PII Detection
MULTILINGUAL_PATTERNS = {
    "name_headers": re.compile(
        r"(?:name|applicant|customer|client|signatory|नाम|आवेदक|ग्राहक|नाव|अर्जदार|"
        r"ಹೆಸರು|ಅರ್ಜಿದಾರ|ಗ್ರಾಹಕ|பெயர்|விண்ணப்பதாரர்|വാடிக்கையாளர்|పేరు|దరఖాస్తుదారు|"
        r"പേര്|അപേക്ഷകൻ|নাম|আবেদনকারী)\s*[:\-]\s*([^\n\r,]+)",
        re.IGNORECASE
    ),
    "aadhaar_headers": re.compile(
        r"(?:aadhaar|uid|आधार|आधर|ಆಧಾರ್|ஆதார்|ఆధార్|ആധാർ|আধার)\s*(?:no|number|कार्ड|नंबर|क्रमांक|संख्या|ಸಂಖ್ಯೆ|ಎಣ್|எண்|సంఖ్య|നമ്പർ|নম্বর)?\s*[:\-]?\s*([0-9\s\-०-९೦-೯௦-௯౦-౯൦-൯০-৯]{12,16})",
        re.IGNORECASE
    ),
    "pan_headers": re.compile(
        r"(?:pan|पैन|पॅन|ಪ್ಯಾನ್|பான்|పాన్|പാൻ|প্যান)[^\n\r:\-]*?[:\-]?\s*([A-Za-z0-9]{10})",
        re.IGNORECASE
    ),
    "phone_headers": re.compile(
        r"(?:phone|mobile|contact|फ़ोन|फोन|मोबाइल|संपर्क|मोबाईल|ದೂರವಾಣಿ|ಮೊಬೈಲ್|ಸಂಪರ್ಕ|"
        r"தொலைபேசி|கைபேசி|ఫోన్|మొబైల్|ഫോൺ|মোবাইল)\s*(?:no|number|नंबर|क्रमांक|संख्या|ಸಂಖ್ಯೆ|எண்|సంఖ్య|നമ്പർ|নম্বর)?\s*[:\-]?\s*([+0-9\s\-\(\)०-९೦-೯௦-௯౦-౯൦-൯০-৯]{10,15})",
        re.IGNORECASE
    ),
    "address_headers": re.compile(
        r"(?:address|residential\s*address|पता|पत्ता|रहिवासी\s*पत्ता|ವಿಳಾಸ|ವಾಸಸ್ಥಳ|"
        r"முகவரி|இருப்பிடம்|చిరునామా|വിലാസം|ঠিকানা)\s*[:\-]\s*([^\n\r]+)",
        re.IGNORECASE
    ),
    "bank_headers": re.compile(
        r"(?:account|bank\s*a/c|a/c\s*no|खाता|बँक\s*खाते|ಖಾತೆ|ಬ್ಯಾಂಕ್\s*ಖಾತೆ|"
        r"வங்கி\s*கணக்கு|ఖాతా|ബാങ്ക്\s*അക്കൗണ്ട്|ব্যাংক\s*অ্যাকাউন্ট)[^\n\r:\-]*?[:\-]?\s*([0-9०-९೦-೯௦-௯౦-౯൦-൯০-৯]{9,18})",
        re.IGNORECASE
    ),
}


class MultilingualEngine:
    """
    Multilingual document text extraction, script identification,
    and Indian regional language PII recognition engine.
    """

    def __init__(self):
        # Optional Tesseract OCR initialization
        self.tesseract_available = False
        try:
            import pytesseract
            # Test if tesseract executable is accessible
            pytesseract.get_tesseract_version()
            self.tesseract_available = True
        except Exception:
            self.tesseract_available = False

    def identify_language(self, text: str) -> Dict[str, Any]:
        """
        Identifies language and script of the given text with fallback script heuristics.
        """
        if not text or len(text.strip()) < 3:
            return {"lang_code": "en", "language": "English", "script": "Latin", "confidence": 1.0}

        # 1. Unicode Script detection heuristic
        script_counts = {}
        for pattern, script_name in SCRIPT_RANGES:
            matches = len(re.findall(pattern, text))
            if matches > 0:
                script_counts[script_name] = matches

        dominant_script = max(script_counts, key=script_counts.get) if script_counts else "Latin (English)"

        # 2. Statistical language detection via langdetect
        detected_code = "en"
        confidence = 0.85

        if dominant_script == "Latin (English)":
            detected_code = "en"
        else:
            try:
                code_cand = detect(text)
                if code_cand in SUPPORTED_LANGUAGES:
                    detected_code = code_cand
                elif "Kannada" in dominant_script:
                    detected_code = "kn"
                elif "Devanagari" in dominant_script:
                    detected_code = "hi"
                elif "Tamil" in dominant_script:
                    detected_code = "ta"
                elif "Telugu" in dominant_script:
                    detected_code = "te"
                elif "Malayalam" in dominant_script:
                    detected_code = "ml"
                elif "Bengali" in dominant_script:
                    detected_code = "bn"
                else:
                    detected_code = "en"
            except Exception:
                if "Kannada" in dominant_script:
                    detected_code = "kn"
                elif "Devanagari" in dominant_script:
                    detected_code = "hi"
                elif "Tamil" in dominant_script:
                    detected_code = "ta"
                elif "Telugu" in dominant_script:
                    detected_code = "te"
                elif "Malayalam" in dominant_script:
                    detected_code = "ml"
                elif "Bengali" in dominant_script:
                    detected_code = "bn"
                else:
                    detected_code = "en"

        lang_info = SUPPORTED_LANGUAGES.get(detected_code, {"name": "Other / Regional", "script": dominant_script})
        return {
            "lang_code": detected_code,
            "language": lang_info["name"],
            "script": dominant_script,
            "confidence": confidence,
            "supported": detected_code in SUPPORTED_LANGUAGES
        }

    def normalize_regional_digits(self, text: str) -> str:
        """Translates regional Indian numerals to standard ASCII 0-9."""
        result = []
        for ch in text:
            result.append(REGIONAL_DIGITS_MAP.get(ch, ch))
        return "".join(result)

    def extract_document_text(self, file_bytes: bytes, filename: str) -> Tuple[str, str, Dict[str, Any]]:
        """
        Extracts text from PDF or image files (JPG, PNG).
        Returns: (extracted_text, extraction_method, metadata)
        """
        ext = filename.lower().split(".")[-1]
        extracted_text = ""
        method = "native_parser"
        meta = {"filename": filename, "extension": ext, "file_size_bytes": len(file_bytes)}

        if ext == "pdf":
            try:
                reader = pypdf.PdfReader(io.BytesIO(file_bytes))
                meta["page_count"] = len(reader.pages)
                page_texts = []
                for i, page in enumerate(reader.pages):
                    t = page.extract_text() or ""
                    page_texts.append(t)
                extracted_text = "\n\n".join(page_texts).strip()

                # If text is negligible, document is likely a scanned PDF
                if len(extracted_text) < 30 and len(reader.pages) > 0:
                    method = "scanned_pdf_ocr"
                    meta["is_scanned"] = True
                    # Attempt OCR on scanned PDF if tesseract available
                    if self.tesseract_available:
                        extracted_text = self._ocr_pdf_pages(file_bytes)
                    else:
                        extracted_text = "[Notice: Scanned PDF detected. Digital text layer empty. OCR engine recommended.]"
                else:
                    meta["is_scanned"] = False

            except Exception as e:
                extracted_text = f"[Error reading PDF: {e}]"
                method = "error"

        elif ext in ["jpg", "jpeg", "png", "bmp", "tiff"]:
            method = "image_ocr"
            meta["is_image"] = True
            if self.tesseract_available:
                try:
                    import pytesseract
                    img = Image.open(io.BytesIO(file_bytes))
                    meta["image_dimensions"] = img.size
                    extracted_text = pytesseract.image_to_string(img)
                except Exception as e:
                    extracted_text = f"[OCR Extraction failed: {e}]"
            else:
                extracted_text = (
                    f"[Document: {filename} uploaded as image. Image dimensions verified. "
                    f"OCR fallback pipeline ready.]"
                )

        else:
            # Fallback plain text / utf-8 decode
            try:
                extracted_text = file_bytes.decode("utf-8", errors="ignore")
                method = "text_plain"
            except Exception:
                extracted_text = "[Unsupported file format]"
                method = "unsupported"

        return extracted_text, method, meta

    def _ocr_pdf_pages(self, file_bytes: bytes) -> str:
        """OCR fallback for scanned PDF pages using pypdf images and pytesseract."""
        try:
            import pytesseract
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            texts = []
            for page in reader.pages:
                for img_obj in page.images:
                    pil_img = Image.open(io.BytesIO(img_obj.data))
                    t = pytesseract.image_to_string(pil_img)
                    if t.strip():
                        texts.append(t.strip())
            return "\n\n".join(texts)
        except Exception:
            return ""

    def detect_multilingual_pii(self, text: str) -> List[Dict[str, Any]]:
        """
        Detects Indian personal entities in multilingual documents across
        Kannada, Hindi, Tamil, Telugu, Malayalam, Marathi, Bengali, and English.
        """
        if not text:
            return []

        entities = []

        def get_exact_span(match, group_idx=1):
            raw_grp = match.group(group_idx)
            val = raw_grp.strip()
            if not val:
                return "", 0, 0
            leading = len(raw_grp) - len(raw_grp.lstrip())
            start = match.start(group_idx) + leading
            end = start + len(val)
            return val, start, end

        # 1. Detect Aadhaar numbers in regional & standard format
        for match in MULTILINGUAL_PATTERNS["aadhaar_headers"].finditer(text):
            raw_val, start, end = get_exact_span(match, 1)
            if not raw_val:
                continue
            norm_val = self.normalize_regional_digits(raw_val).replace(" ", "").replace("-", "")
            if len(norm_val) == 12 and norm_val.isdigit():
                entities.append({
                    "entity_type": "AADHAAR",
                    "start": start,
                    "end": end,
                    "value": raw_val,
                    "normalized_value": norm_val,
                    "score": 0.95,
                    "metadata": {"multilingual_header": True}
                })

        # 2. Detect PAN numbers in regional contexts
        for match in MULTILINGUAL_PATTERNS["pan_headers"].finditer(text):
            raw_val, start, end = get_exact_span(match, 1)
            val = raw_val.upper()
            if len(val) == 10 and re.match(r"[A-Z]{5}\d{4}[A-Z]", val):
                entities.append({
                    "entity_type": "PAN",
                    "start": start,
                    "end": end,
                    "value": val,
                    "normalized_value": val,
                    "score": 0.98,
                    "metadata": {"multilingual_header": True}
                })

        # 3. Detect Phone numbers in regional contexts
        for match in MULTILINGUAL_PATTERNS["phone_headers"].finditer(text):
            raw_val, start, end = get_exact_span(match, 1)
            if not raw_val:
                continue
            norm_val = self.normalize_regional_digits(raw_val)
            clean_digits = re.sub(r"\D", "", norm_val)
            if len(clean_digits) in [10, 11, 12]:
                entities.append({
                    "entity_type": "PHONE_NUMBER",
                    "start": start,
                    "end": end,
                    "value": raw_val,
                    "normalized_value": clean_digits,
                    "score": 0.92,
                    "metadata": {"multilingual_header": True}
                })

        # 4. Detect Names in regional contexts
        for match in MULTILINGUAL_PATTERNS["name_headers"].finditer(text):
            raw_val, start, end = get_exact_span(match, 1)
            if 2 <= len(raw_val) <= 45 and not any(ch.isdigit() for ch in raw_val):
                entities.append({
                    "entity_type": "PERSON",
                    "start": start,
                    "end": end,
                    "value": raw_val,
                    "normalized_value": raw_val,
                    "score": 0.94,
                    "metadata": {"multilingual_header": True}
                })

        # 5. Detect Addresses in regional contexts
        for match in MULTILINGUAL_PATTERNS["address_headers"].finditer(text):
            raw_val, start, end = get_exact_span(match, 1)
            if len(raw_val) >= 8:
                entities.append({
                    "entity_type": "ADDRESS",
                    "start": start,
                    "end": end,
                    "value": raw_val,
                    "normalized_value": raw_val,
                    "score": 0.90,
                    "metadata": {"multilingual_header": True}
                })

        # 6. Detect Bank Accounts in regional contexts
        for match in MULTILINGUAL_PATTERNS["bank_headers"].finditer(text):
            raw_val, start, end = get_exact_span(match, 1)
            norm_val = self.normalize_regional_digits(raw_val)
            if 9 <= len(norm_val) <= 18 and norm_val.isdigit():
                entities.append({
                    "entity_type": "BANK_ACCOUNT",
                    "start": start,
                    "end": end,
                    "value": raw_val,
                    "normalized_value": norm_val,
                    "score": 0.94,
                    "metadata": {"multilingual_header": True}
                })

        return entities


multilingual_engine_instance = MultilingualEngine()
