"""
PRIVOPS - Indian PII Recognizers & Checksum Validators
Implements mathematical checksum validation (Verhoeff for Aadhaar),
regex patterns, and format validators for Indian personal identifiers.
"""

import re
from typing import List, Dict, Any, Optional, Tuple

# ==========================================
# 1. VERHOEFF ALGORITHM (Aadhaar Checksum)
# ==========================================
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """Validates Verhoeff checksum for Aadhaar (12 digits)."""
    clean_num = re.sub(r"[\s\-]", "", str(num_str))
    if not clean_num.isdigit() or len(clean_num) != 12:
        return False
    # Aadhaar cannot start with 0 or 1 according to UIDAI specifications
    if clean_num[0] in ('0', '1'):
        return False
    c = 0
    for i, item in enumerate(reversed(clean_num)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(item)]]
    return c == 0


def generate_verhoeff_checksum(prefix_11: str) -> str:
    """Generates the 12th Verhoeff checksum digit for an 11-digit prefix."""
    clean_prefix = re.sub(r"[\s\-]", "", str(prefix_11))
    c = 0
    for i, item in enumerate(reversed(clean_prefix)):
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][int(item)]]
    return clean_prefix + str(VERHOEFF_INV[c])


# ==========================================
# 2. INDIAN PII PATTERNS & VALIDATORS
# ==========================================

# Aadhaar: 12 digits, often formatted as 4-4-4 (e.g. 5432 1234 5678 or 5432-1234-5678 or 543212345678)
AADHAAR_REGEX = re.compile(r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b")

# PAN: 5 uppercase letters + 4 digits + 1 uppercase letter
# 4th character conventionally denotes entity: P(Person), C(Company), H(HUF), F(Firm), A(AOP), T(Trust), B(BOI), L(Local Auth), J(AJP), G(Govt)
PAN_REGEX = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

# GSTIN: 2-digit state code (01-37, 97) + 10-char PAN + 1 entity code + Z + 1 check digit (15 chars)
GSTIN_REGEX = re.compile(r"\b(0[1-9]|[1-2]\d|3[0-7]|97)[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")

# Voter ID (EPIC): 3 letters followed by 7 digits
VOTER_ID_REGEX = re.compile(r"\b[A-Z]{3}[0-9]{7}\b")

# Indian Passport: 1 uppercase letter (typically A, B, C, D, E, F, G, H, J, K, L, M, N, P, R, S, T, U, V, W, X, Y, Z) + 7 digits
PASSPORT_REGEX = re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d{6}\b")

# Indian Phone: +91 or 0 or without prefix, 10 digits starting with 6, 7, 8, 9
PHONE_REGEX = re.compile(r"(?:(?:\+91|91|0)[-.\s]?)?[6-9]\d{9}\b")

# Email Address
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# IFSC Code: 4 letters + 0 + 6 alphanumeric
IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

# Bank Account Number: 9 to 18 digits with contextual keywords
BANK_ACC_KEYWORD_REGEX = re.compile(
    r"(?:a/c|account\s*no\.?|account\s*number|bank\s*a/c|bank\s*account|savings\s*a/c|current\s*a/c)\s*[:#-]?\s*(\d{9,18})\b",
    re.IGNORECASE
)

# Indian Pin Code (6 digits, first digit 1-9)
PINCODE_REGEX = re.compile(r"\b[1-9]\d{5}\b")

# Common Indian Address Markers
ADDRESS_MARKERS = [
    "flat", "apartment", "apt", "plot", "house", "door no", "building", "floor",
    "street", "road", "marg", "lane", "rasta", "path", "gali", "cross", "main",
    "nagar", "colony", "enclave", "vihar", "society", "layout", "sector", "phase",
    "near", "opposite", "opp", "behind", "beside", "adjacent", "landmark",
    "pincode", "pin code", "pin", "po", "post office", "district", "dist"
]

MAJOR_INDIAN_CITIES = {
    "mumbai", "delhi", "bengaluru", "bangalore", "hyderabad", "ahmedabad", "chennai",
    "kolkata", "surat", "pune", "jaipur", "lucknow", "kanpur", "nagpur", "indore",
    "thane", "bhopal", "visakhapatnam", "patna", "vadodara", "ghaziabad", "ludhiana",
    "agra", "nashik", "faridabad", "meerut", "rajkot", "varanasi", "srinagar",
    "aurangabad", "dhanbad", "amritsar", "navi mumbai", "allahabad", "prayagraj",
    "ranchi", "howrah", "coimbatore", "jabalpur", "gwalior", "vijayawada", "jodhpur",
    "madurai", "raipur", "kota", "chandigarh", "guwahati", "solapur", "hubli", "noida",
    "gurgaon", "gurugram", "dehradun", "mysore", "mysuru", "bhubaneswar", "kochi", "trivandrum"
}

INDIAN_STATES = {
    "andhra pradesh", "arunachal pradesh", "assam", "bihar", "chhattisgarh", "goa",
    "gujarat", "haryana", "himachal pradesh", "jharkhand", "karnataka", "kerala",
    "madhya pradesh", "maharashtra", "manipur", "meghalaya", "mizoram", "nagaland",
    "odisha", "punjab", "rajasthan", "sikkim", "tamil nadu", "telangana", "tripura",
    "uttar pradesh", "uttarakhand", "west bengal", "delhi", "jammu & kashmir", "ladakh"
}


# ==========================================
# 3. RECOGNIZER CLASS & MATCH EXTRACTION
# ==========================================

class IndianPIIRecognizers:
    """High-accuracy recognizer collection for Indian enterprise PII entities."""

    @staticmethod
    def find_aadhaar(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in AADHAAR_REGEX.finditer(text):
            val = match.group(0)
            clean = re.sub(r"[\s\-]", "", val)
            # Check Verhoeff checksum
            is_valid_verhoeff = validate_verhoeff(clean)
            # Aadhaar numbers have 12 digits; give higher score if Verhoeff passes
            score = 1.0 if is_valid_verhoeff else 0.85
            matches.append({
                "entity_type": "AADHAAR",
                "start": match.start(),
                "end": match.end(),
                "value": val,
                "score": score,
                "metadata": {
                    "clean_value": clean,
                    "verhoeff_valid": is_valid_verhoeff
                }
            })
        return matches

    @staticmethod
    def find_pan(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in PAN_REGEX.finditer(text):
            val = match.group(0)
            # 4th letter entity type
            entity_category = {
                'P': 'Individual',
                'C': 'Company',
                'H': 'HUF',
                'F': 'Firm',
                'A': 'AOP',
                'T': 'Trust',
                'B': 'BOI',
                'L': 'Local Authority',
                'J': 'Artificial Juridical Person',
                'G': 'Government'
            }.get(val[3], 'Unknown')

            matches.append({
                "entity_type": "PAN",
                "start": match.start(),
                "end": match.end(),
                "value": val,
                "score": 0.98,
                "metadata": {
                    "taxpayer_type": entity_category
                }
            })
        return matches

    @staticmethod
    def find_gstin(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in GSTIN_REGEX.finditer(text):
            val = match.group(0)
            state_code = val[:2]
            pan_component = val[2:12]
            matches.append({
                "entity_type": "GSTIN",
                "start": match.start(),
                "end": match.end(),
                "value": val,
                "score": 0.99,
                "metadata": {
                    "state_code": state_code,
                    "pan_component": pan_component
                }
            })
        return matches

    @staticmethod
    def find_voter_id(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in VOTER_ID_REGEX.finditer(text):
            val = match.group(0)
            # Check context or preceding keywords to avoid generic 3-char + 7-digit strings
            start = match.start()
            ctx = text[max(0, start - 25):start].lower()
            score = 0.95 if any(k in ctx for k in ["voter", "epic", "election", "card", "id"]) else 0.80
            matches.append({
                "entity_type": "VOTER_ID",
                "start": match.start(),
                "end": match.end(),
                "value": val,
                "score": score,
                "metadata": {}
            })
        return matches

    @staticmethod
    def find_passport(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in PASSPORT_REGEX.finditer(text):
            val = match.group(0)
            start = match.start()
            ctx = text[max(0, start - 25):start].lower()
            score = 0.95 if any(k in ctx for k in ["passport", "ppt", "travel", "doc"]) else 0.75
            matches.append({
                "entity_type": "PASSPORT",
                "start": match.start(),
                "end": match.end(),
                "value": val,
                "score": score,
                "metadata": {}
            })
        return matches

    @staticmethod
    def find_phone(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in PHONE_REGEX.finditer(text):
            val = match.group(0)
            # Normalize
            clean = re.sub(r"[\s\-+.]", "", val)
            if clean.startswith("91") and len(clean) == 12:
                clean = clean[2:]
            elif clean.startswith("0") and len(clean) == 11:
                clean = clean[1:]

            if len(clean) == 10 and clean[0] in "6789":
                matches.append({
                    "entity_type": "PHONE_NUMBER",
                    "start": match.start(),
                    "end": match.end(),
                    "value": val,
                    "score": 0.90,
                    "metadata": {"normalized": clean}
                })
        return matches

    @staticmethod
    def find_email(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in EMAIL_REGEX.finditer(text):
            val = match.group(0)
            matches.append({
                "entity_type": "EMAIL_ADDRESS",
                "start": match.start(),
                "end": match.end(),
                "value": val,
                "score": 1.0,
                "metadata": {}
            })
        return matches

    @staticmethod
    def find_bank_account(text: str) -> List[Dict[str, Any]]:
        matches = []
        for match in BANK_ACC_KEYWORD_REGEX.finditer(text):
            acc_num = match.group(1)
            # Find the exact span of the account number
            start = match.start(1)
            end = match.end(1)
            matches.append({
                "entity_type": "BANK_ACCOUNT",
                "start": start,
                "end": end,
                "value": acc_num,
                "score": 0.95,
                "metadata": {"account_length": len(acc_num)}
            })
        # Check IFSC codes
        for match in IFSC_REGEX.finditer(text):
            matches.append({
                "entity_type": "BANK_ACCOUNT",
                "start": match.start(),
                "end": match.end(),
                "value": match.group(0),
                "score": 0.98,
                "metadata": {"type": "IFSC"}
            })
        return matches

    @staticmethod
    def find_address(text: str) -> List[Dict[str, Any]]:
        """
        Detects Indian street/residential addresses using markers, pincodes, and city names.
        """
        matches = []
        # Pattern for addresses ending with or containing Pincode
        # e.g.: "Flat 402, Shanti Heights, MG Road, Indiranagar, Bengaluru - 560038"
        address_chunk_regex = re.compile(
            r"((?:(?:Flat|Plot|House|Apt|Door\s*No|Building|H\.?No|Sector|Phase|Shop|Survey)\s*[\w\d\-\/]+[\s,]+)"
            r"[A-Za-z0-9\s,.\-\/]+"
            r"(?:\b[1-9]\d{5}\b|[A-Za-z]+[\s,]+[1-9]\d{5}\b))",
            re.IGNORECASE
        )

        for match in address_chunk_regex.finditer(text):
            val = match.group(0).strip()
            # Validate if it contains at least one address marker or Indian city
            lower_val = val.lower()
            has_marker = any(m in lower_val for m in ADDRESS_MARKERS)
            has_city = any(c in lower_val for c in MAJOR_INDIAN_CITIES)
            has_pin = bool(PINCODE_REGEX.search(val))

            if has_marker or (has_city and has_pin):
                matches.append({
                    "entity_type": "ADDRESS",
                    "start": match.start(),
                    "end": match.end(),
                    "value": val,
                    "score": 0.88,
                    "metadata": {
                        "has_pincode": has_pin,
                        "has_city": has_city
                    }
                })

        # Also search for standalone labeled addresses: "Address: Flat 301, ..., Mumbai"
        labeled_address_regex = re.compile(
            r"(?:Address|Residential\s*Address|Permanent\s*Address|Current\s*Address)\s*[:\-]\s*([^\n\r]+)",
            re.IGNORECASE
        )
        for match in labeled_address_regex.finditer(text):
            val = match.group(1).strip()
            if len(val) > 10 and not any(m["start"] <= match.start(1) and m["end"] >= match.end(1) for m in matches):
                matches.append({
                    "entity_type": "ADDRESS",
                    "start": match.start(1),
                    "end": match.end(1),
                    "value": val,
                    "score": 0.92,
                    "metadata": {"labeled": True}
                })

        return matches
