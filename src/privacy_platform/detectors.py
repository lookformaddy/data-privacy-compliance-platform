"""PII detectors: regex patterns + field-name dictionary signals.

Design notes
------------
* A detector never returns a full secret: ``Finding.matched_value`` holds a
  truncated (<= 12 char) sample used only for debugging classification.
* Pattern confidence is deliberately < 1.0: a regex hit is evidence, not
  proof (e.g. a 16-digit order reference is not a card number). The Luhn
  check on card candidates is what lifts a card hit to high confidence.
* Dictionary hits (field *names* like ``email`` or ``ssn``) are a separate
  signal; :mod:`privacy_platform.classification` combines the two, so a
  column named ``email`` full of malformed values still classifies, just
  at lower confidence than one whose values also match the pattern.
"""

from __future__ import annotations

import re

from privacy_platform.models import Finding, PIICategory

_TRUNC = 12


def _sample(value: str) -> str:
    return value[:_TRUNC] + ("…" if len(value) > _TRUNC else "")


def luhn_ok(digits: str) -> bool:
    """Luhn checksum; True only for digit strings that pass the check."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class PatternDetector:
    """Regex detectors over raw values."""

    name = "pattern"

    EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    PHONE_RE = re.compile(r"^\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$")
    SSN_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")
    CC_RE = re.compile(r"^[\d][\d -]{11,18}[\d]$")
    IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})$")

    def scan_value(self, field: str, value: str) -> list[Finding]:
        if value is None:
            return []
        text = str(value).strip()
        if not text:
            return []
        findings: list[Finding] = []
        if self.EMAIL_RE.match(text):
            findings.append(Finding(field, PIICategory.EMAIL, 0.95, self.name, _sample(text)))
        if self.PHONE_RE.match(text):
            findings.append(Finding(field, PIICategory.PHONE, 0.85, self.name, _sample(text)))
        if self.SSN_RE.match(text):
            # 000/666/900-999 area numbers are never issued; still PII-shaped,
            # but downgrade so synthetic test data does not over-claim.
            area = int(text[:3])
            conf = 0.80 if area in (0, 666) or area >= 900 else 0.95
            findings.append(Finding(field, PIICategory.SSN, conf, self.name, _sample(text)))
        if self.CC_RE.match(text):
            digits = re.sub(r"\D", "", text)
            if luhn_ok(digits):
                findings.append(Finding(field, PIICategory.CREDIT_CARD, 0.95, self.name, _sample(text)))
            # Without a Luhn pass a long digit string is not claimed as a card.
        if self.IP_RE.match(text) and all(0 <= int(o) <= 255 for o in text.split(".")):
            findings.append(Finding(field, PIICategory.IP_ADDRESS, 0.90, self.name, _sample(text)))
        if self.DATE_RE.match(text) and _looks_like_dob(field):
            findings.append(Finding(field, PIICategory.DATE_OF_BIRTH, 0.75, self.name, _sample(text)))
        return findings


def _looks_like_dob(field: str) -> bool:
    lowered = field.lower()
    return any(token in lowered for token in ("dob", "birth", "birthdate", "birth_date"))


# Field-name tokens -> category. Checked as substring tokens so
# ``customer_email`` and ``email_address`` both match.
FIELD_KEYWORDS: dict[str, PIICategory] = {
    "email": PIICategory.EMAIL,
    "ssn": PIICategory.SSN,
    "social_security": PIICategory.SSN,
    "phone": PIICategory.PHONE,
    "mobile": PIICategory.PHONE,
    "telephone": PIICategory.PHONE,
    "credit_card": PIICategory.CREDIT_CARD,
    "card_number": PIICategory.CREDIT_CARD,
    "card": PIICategory.CREDIT_CARD,
    "address": PIICategory.ADDRESS,
    "street": PIICategory.ADDRESS,
    "dob": PIICategory.DATE_OF_BIRTH,
    "date_of_birth": PIICategory.DATE_OF_BIRTH,
    "birthdate": PIICategory.DATE_OF_BIRTH,
    "birth_date": PIICategory.DATE_OF_BIRTH,
    "first_name": PIICategory.NAME,
    "last_name": PIICategory.NAME,
    "full_name": PIICategory.NAME,
    "customer_name": PIICategory.NAME,
    "ip": PIICategory.IP_ADDRESS,
    "ip_address": PIICategory.IP_ADDRESS,
    "customer_id": PIICategory.ACCOUNT_ID,
    "user_id": PIICategory.ACCOUNT_ID,
    "account_id": PIICategory.ACCOUNT_ID,
}


class DictionaryDetector:
    """Field-name dictionary detector (no value inspection)."""

    name = "dictionary"

    def category_for_field(self, field: str) -> PIICategory | None:
        lowered = field.lower()
        # Longest keyword first so ``card_number`` wins over ``card`` etc.
        for keyword in sorted(FIELD_KEYWORDS, key=len, reverse=True):
            if keyword in lowered:
                return FIELD_KEYWORDS[keyword]
        if lowered in ("name",) or lowered.endswith("_name"):
            return PIICategory.NAME
        return None

    def scan_value(self, field: str, value: str) -> list[Finding]:
        category = self.category_for_field(field)
        if category is None or value is None or str(value).strip() == "":
            return []
        return [Finding(field, category, 0.70, self.name, _sample(str(value)))]


DEFAULT_DETECTORS = [PatternDetector(), DictionaryDetector()]
