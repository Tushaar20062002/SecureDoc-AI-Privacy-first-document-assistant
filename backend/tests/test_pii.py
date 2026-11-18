"""Unit tests for local PII detection (synthetic values only)."""
from app.services import pii_service as p


def _cats(text):
    return {(e.category, e.text) for e in p.detect(text)}


def test_detects_all_required_categories():
    text = "\n".join([
        "Full Name: Ravi Shankar Mehta",
        "Residential Address: 12 Lake View, Ring Road, Nagpur 440001",
        "Email: synthetic.user@example.com",
        "Mobile: 9876543210",
        "Date of Birth: 01/01/1990",
        "Aadhaar No: 2345 6789 0124",
        "PAN: ABCPM1234Q",
        "Passport No: K1234567",
        "Account Number: 001122334455",
        "IFSC: SBIN0001234",
        "Card Number: 4111 1111 1111 1111",
        "Password: hunter2!",
        "ATM PIN: 4321",
        "OTP: 556677",
        "Login IP: 192.168.10.20",
        "Voter ID: XYZ1234567",
    ])
    cats = {e.category for e in p.detect(text)}
    for c in ("PERSON", "ADDRESS", "EMAIL", "PHONE", "DOB", "AADHAAR", "PAN", "PASSPORT", "BANK_ACCOUNT",
              "IFSC", "CREDIT_CARD", "PASSWORD", "PIN", "OTP", "IP_ADDRESS", "OTHER_ID"):
        assert c in cats, c


def test_unlabelled_identifiers():
    cats = {e.category for e in p.detect("contact a.b@example.com or 9876543210, PAN ABCPM1234Q card 4111111111111111")}
    assert {"EMAIL", "PHONE", "PAN", "CREDIT_CARD"} <= cats


def test_pincode_label_not_treated_as_pin():
    cats = {(e.category) for e in p.detect("PIN Code: 411001")}
    assert "PIN" not in cats and "ADDRESS" in cats


def test_company_name_not_masked_as_person():
    assert not any(e.category == "PERSON" for e in p.detect("Company Name: Infosys Limited"))


def test_honorific_heuristic_flagged_lower_confidence():
    ents = [e for e in p.detect("The form was signed by Mr. Arjun Kapoor yesterday.") if e.category == "PERSON"]
    assert ents and ents[0].text == "Arjun Kapoor"
    assert ents[0].confidence < 0.9  # heuristic NER detections carry lower confidence


def test_checksums():
    assert p.luhn_valid("4111111111111111")
    assert not p.luhn_valid("4111111111111112")
    # Verhoeff: append computed check digit and validate
    base = "23456789012"
    valid = next(base + str(d) for d in range(10) if p.verhoeff_valid(base + str(d)))
    assert p.verhoeff_valid(valid)


def test_propagation_masks_every_occurrence():
    text = "Full Name: Kiran Rao\nDeclaration: I, Kiran Rao, confirm. Signed Kiran."
    ents = [e for e in p.detect(text) if e.category == "PERSON"]
    assert len(ents) >= 3


def test_x_mask_is_format_preserving_and_reveals_nothing():
    from app.services.masking_service import x_mask

    assert x_mask("2345 6789 0124") == "XXXX XXXX XXXX"
    assert x_mask("ravi.m@example.com") == "XXXX.X@XXXXXXX.XXX"
    assert x_mask("+91 98765 43210") == "+XX XXXXX XXXXX"
    assert not any(c.isdigit() for c in x_mask("ABCPM1234Q"))


def test_mask_restricted_inline():
    out = p.mask_restricted_inline("PAN ABCPM1234Q and Aadhaar 2345 6789 0124")
    assert "ABCPM1234Q" not in out and "6789" not in out
