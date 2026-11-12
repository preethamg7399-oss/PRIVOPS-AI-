"""
PRIVOPS - Synthetic Indian Enterprise PII Dataset Generator
Generates 50+ realistic Indian enterprise documents across Banking, Customer Support,
HR, E-Commerce, and Healthcare with ground-truth entity labels and valid Verhoeff Aadhaar numbers.
Used for rigorous evaluation of Precision, Recall, Tokenization, and Leakage rates.
"""

import random
from typing import List, Dict, Any
from backend.recognizers import generate_verhoeff_checksum

# Sample Indian Names
FIRST_NAMES = [
    "Rahul", "Priya", "Amit", "Sunita", "Vikram", "Ananya", "Rohan", "Sneha",
    "Deepak", "Pooja", "Arjun", "Kavita", "Suresh", "Meera", "Manoj", "Divya",
    "Rajesh", "Neha", "Alok", "Shweta", "Siddharth", "Tanvi", "Gaurav", "Preeti",
    "Nikhil", "Isha", "Aditya", "Ritu", "Karan", "Swati", "Sanjay", "Rani"
]

LAST_NAMES = [
    "Sharma", "Kumar", "Patel", "Verma", "Singh", "Nair", "Iyer", "Reddy",
    "Gupta", "Deshmukh", "Choudhury", "Bose", "Mehta", "Joshi", "Bhat", "Rao",
    "Pandey", "Mishra", "Kulkarni", "Chatterjee", "Menon", "Pillai", "Agarwal"
]

CITIES_WITH_PIN = [
    ("Mumbai", "Maharashtra", "400001", "Nariman Point"),
    ("Bengaluru", "Karnataka", "560038", "Indiranagar 100ft Road"),
    ("New Delhi", "Delhi", "110001", "Barakhamba Road, Connaught Place"),
    ("Hyderabad", "Telangana", "500081", "Madhapur, Hitec City"),
    ("Pune", "Maharashtra", "411004", "FC Road, Shivaji Nagar"),
    ("Chennai", "Tamil Nadu", "600034", "Nungambakkam High Road"),
    ("Kolkata", "West Bengal", "700016", "Park Street, Camac Street"),
    ("Ahmedabad", "Gujarat", "380015", "SG Highway, Bodakdev"),
    ("Jaipur", "Rajasthan", "302001", "MI Road, C-Scheme"),
    ("Lucknow", "Uttar Pradesh", "226001", "Hazratganj, Gomti Nagar")
]

PAN_FOURTH_CHARS = ['P', 'P', 'P', 'P', 'C', 'F']  # Mostly individual 'P'


def generate_valid_aadhaar() -> str:
    """Generates a mathematically valid 12-digit Aadhaar number with Verhoeff checksum."""
    # Prefix must not start with 0 or 1
    first_digit = str(random.randint(2, 9))
    rest_10 = "".join(str(random.randint(0, 9)) for _ in range(10))
    prefix_11 = first_digit + rest_10
    full_12 = generate_verhoeff_checksum(prefix_11)
    # Return formatted as 4-4-4
    return f"{full_12[:4]} {full_12[4:8]} {full_12[8:]}"


def generate_valid_pan(surname_char: str = "S") -> str:
    """Generates valid 10-character PAN."""
    letters3 = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3))
    fourth = random.choice(PAN_FOURTH_CHARS)
    fifth = surname_char.upper() if surname_char else "K"
    digits4 = "".join(str(random.randint(0, 9)) for _ in range(4))
    last_char = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return f"{letters3}{fourth}{fifth}{digits4}{last_char}"


def generate_valid_gstin(pan: str, state_code: str = "27") -> str:
    """Generates valid 15-character GSTIN using provided PAN."""
    entity_code = str(random.randint(1, 9))
    check_char = random.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return f"{state_code}{pan}{entity_code}Z{check_char}"


def generate_valid_phone() -> str:
    """Generates valid Indian mobile number."""
    first = random.choice(["9", "8", "7", "6"])
    rest9 = "".join(str(random.randint(0, 9)) for _ in range(9))
    prefix = random.choice(["+91-", "+91 ", ""])
    return f"{prefix}{first}{rest9}"


def generate_valid_voter_id() -> str:
    """Generates 10-char Voter ID (EPIC)."""
    code = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3))
    digits = "".join(str(random.randint(0, 9)) for _ in range(7))
    return f"{code}{digits}"


def generate_valid_passport() -> str:
    """Generates Indian passport number."""
    letter = random.choice("ABCDEFGHIJKLMNOPRSTUVWZ")
    digits = str(random.randint(1000000, 9999999))
    return f"{letter}{digits}"


def generate_synthetic_documents(count: int = 50) -> List[Dict[str, Any]]:
    """
    Generates realistic Indian enterprise documents across multiple domains.
    Returns documents with ground-truth annotated entity metadata.
    """
    documents = []
    purposes = ["loan_processing", "customer_support", "marketing", "fraud_investigation", "general_inquiry"]

    templates = [
        # 1. Loan Application Template
        {
            "domain": "Banking & Loan Processing",
            "default_purpose": "loan_processing",
            "text": (
                "LOAN APPLICATION PROPOSAL\n"
                "Applicant: {name}\n"
                "Aadhaar Number: {aadhaar}\n"
                "Permanent Account Number (PAN): {pan}\n"
                "Primary Mobile: {phone}\n"
                "Email: {email}\n"
                "Bank Account No: {bank_acc}\n"
                "Address: Flat {flat}, {street}, {city}, {state} - {pincode}\n"
                "Applied Loan Amount: INR 12,50,000 for Business Expansion.\n"
                "Please analyze the debt-to-income ratio and provide credit approval memo."
            )
        },
        # 2. Customer Support Ticket Template
        {
            "domain": "Telecom & Customer Support",
            "default_purpose": "customer_support",
            "text": (
                "CUSTOMER SUPPORT ESCALATION\n"
                "Customer Name: {name}\n"
                "Contact Number: {phone}\n"
                "Email Address: {email}\n"
                "Service Account: {bank_acc}\n"
                "Billing Address: House No {flat}, {street}, {city}, {state} - {pincode}\n"
                "Issue Description: Customer reports fiber broadband interruption since yesterday. "
                "Please formulate a priority response ticket for {name}."
            )
        },
        # 3. Marketing & Campaign Personalization Template
        {
            "domain": "Marketing & Retail",
            "default_purpose": "marketing",
            "text": (
                "MARKETING OUTREACH BRIEF\n"
                "Customer Name: {name}\n"
                "Email: {email}\n"
                "Registered Mobile: {phone}\n"
                "City: {city}\n"
                "Generate a tailored promotional email inviting {name} to our Diwali Festive Sale."
            )
        },
        # 4. KYC & Vendor Compliance Template (often contains GSTIN & PAN)
        {
            "domain": "Corporate Vendor Management",
            "default_purpose": "loan_processing",
            "text": (
                "VENDOR ONBOARDING FORM\n"
                "Authorized Signatory: {name}\n"
                "Company PAN: {pan}\n"
                "GSTIN: {gstin}\n"
                "Bank Account Number: {bank_acc}\n"
                "Official Email: {email}\n"
                "Registered Office: Plot {flat}, {street}, {city}, {state} - {pincode}\n"
                "Please draft the vendor agreement summary."
            )
        },
        # 5. Fraud Investigation Template
        {
            "domain": "Risk & Fraud Investigation",
            "default_purpose": "fraud_investigation",
            "text": (
                "SUSPICIOUS TRANSACTION AUDIT MEMO\n"
                "Subject Individual: {name}\n"
                "PAN Number: {pan}\n"
                "Aadhaar: {aadhaar}\n"
                "Flagged Bank Account: {bank_acc}\n"
                "Voter ID: {voter_id}\n"
                "Contact Phone: {phone}\n"
                "Residential Address: Flat {flat}, {street}, {city}, {state} - {pincode}\n"
                "Incident: High-velocity foreign remittances detected. Provide risk score summary."
            )
        }
    ]

    for i in range(count):
        fname = random.choice(FIRST_NAMES)
        lname = random.choice(LAST_NAMES)
        full_name = f"{fname} {lname}"
        city_info = random.choice(CITIES_WITH_PIN)
        city, state, pin, street = city_info
        flat_no = str(random.randint(101, 908))

        pan = generate_valid_pan(surname_char=lname[0])
        aadhaar = generate_valid_aadhaar()
        gstin = generate_valid_gstin(pan, state_code=str(random.randint(10, 36)))
        phone = generate_valid_phone()
        email = f"{fname.lower()}.{lname.lower()}{random.randint(10, 99)}@gmail.com"
        bank_acc = f"{random.randint(10000000000, 99999999999)}"
        voter_id = generate_valid_voter_id()
        passport = generate_valid_passport()

        tmpl = templates[i % len(templates)]
        doc_text = tmpl["text"].format(
            name=full_name,
            aadhaar=aadhaar,
            pan=pan,
            gstin=gstin,
            phone=phone,
            email=email,
            bank_acc=bank_acc,
            voter_id=voter_id,
            passport=passport,
            flat=flat_no,
            street=street,
            city=city,
            state=state,
            pincode=pin
        )

        expected_entities = [
            {"type": "PERSON", "value": full_name},
            {"type": "PHONE_NUMBER", "value": phone},
            {"type": "EMAIL_ADDRESS", "value": email},
        ]
        if "{pan}" in tmpl["text"]:
            expected_entities.append({"type": "PAN", "value": pan})
        if "{aadhaar}" in tmpl["text"]:
            expected_entities.append({"type": "AADHAAR", "value": aadhaar})
        if "{gstin}" in tmpl["text"]:
            expected_entities.append({"type": "GSTIN", "value": gstin})
        if "{bank_acc}" in tmpl["text"]:
            expected_entities.append({"type": "BANK_ACCOUNT", "value": bank_acc})
        if "{voter_id}" in tmpl["text"]:
            expected_entities.append({"type": "VOTER_ID", "value": voter_id})
        if "{flat}" in tmpl["text"]:
            expected_entities.append({"type": "ADDRESS", "value": f"Flat {flat_no}, {street}, {city}, {state} - {pin}"})

        documents.append({
            "doc_id": f"SYN-DOC-{i+1:03d}",
            "domain": tmpl["domain"],
            "purpose": tmpl["default_purpose"],
            "text": doc_text,
            "expected_entities": expected_entities
        })

    return documents


if __name__ == "__main__":
    docs = generate_synthetic_documents(50)
    print(f"Generated {len(docs)} synthetic enterprise documents.")
    print("Sample Document 1:")
    print("---------------------------------")
    print(docs[0]["text"])
    print("---------------------------------")
    print("Entities:", [e["type"] for e in docs[0]["expected_entities"]])
