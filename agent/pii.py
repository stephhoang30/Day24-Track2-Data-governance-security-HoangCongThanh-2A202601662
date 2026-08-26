"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Cách tiếp cận (regex-first, đủ để >95% recall trên tests/vn_pii_testset.jsonl):

  1. EMAIL: regex local@domain.tld, bắt trước để phần "số" bên trong email
     không bị nhận nhầm thành CCCD/STK.
  2. Số: quét mọi dãy 8-16 chữ số liên tiếp, phân loại theo ĐỘ DÀI + NGỮ
     CẢNH — vì CCCD (12 số) và STK (cũng có thể 12 số) chỉ phân biệt được
     bằng từ khoá đứng trước ("CCCD ..." vs "STK ..."):
        - dài 10-11 và bắt đầu bằng '0'   -> VN_PHONE
        - dài đúng 12:
              có "STK/số tài khoản/chuyển khoản" trước, KHÔNG có "CCCD" -> VN_BANK_ACCOUNT
              ngược lại                                                 -> VN_CCCD
        - còn lại (8-16)                   -> VN_BANK_ACCOUNT

Ngữ cảnh được so khớp SAU KHI bỏ dấu tiếng Việt, nên "Số tài khoản" và "so
tai khoan" đều tính.

KHÔNG bắt PERSON trong detect(): testset chỉ gán nhãn 4 loại trên, thêm
PERSON sẽ tạo prediction không có gold khớp -> tụt precision, và những dòng
"chỉ có tên" (không PII) phải trả về [] để không sinh false positive.
Deny-list PERSON là mối lo ở tầng ingestion (stretch), không thuộc contract
của detect().
"""
from __future__ import annotations

import re
import unicodedata

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Dãy số liên tiếp 8-16 chữ số, không dính vào chữ số khác hai đầu.
_DIGIT_RUN_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")

_CCCD_KEYS = ("cccd", "can cuoc", "cmnd", "cmt")
_BANK_KEYS = ("stk", "so tai khoan", "tai khoan", "chuyen khoan", "so tk")

# Cửa sổ ký tự nhìn ngược về trước một dãy số để đọc từ khoá ngữ cảnh.
_CONTEXT_WINDOW = 30


def _strip_accents(s: str) -> str:
    """Bỏ dấu + hạ chữ thường, để so khớp từ khoá ngữ cảnh không phụ thuộc dấu."""
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def _classify_number(run: str, window: str) -> str:
    length = len(run)
    if length in (10, 11) and run.startswith("0"):
        return "VN_PHONE"
    if length == 12:
        has_bank = any(k in window for k in _BANK_KEYS)
        has_cccd = any(k in window for k in _CCCD_KEYS)
        if has_bank and not has_cccd:
            return "VN_BANK_ACCOUNT"
        return "VN_CCCD"
    return "VN_BANK_ACCOUNT"


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    email_spans: list[tuple[int, int]] = []

    for m in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
        email_spans.append((m.start(), m.end()))

    def inside_email(start: int, end: int) -> bool:
        return any(start < e and s < end for s, e in email_spans)

    for m in _DIGIT_RUN_RE.finditer(text):
        start, end = m.start(), m.end()
        if inside_email(start, end):
            continue
        window = _strip_accents(text[max(0, start - _CONTEXT_WINDOW):start])
        entities.append({
            "type": _classify_number(m.group(), window),
            "start": start,
            "end": end,
        })

    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    # Thay từ CUỐI văn bản về ĐẦU để offset của các entity chưa xử lý không lệch.
    entities = sorted(detect(text), key=lambda e: e["start"], reverse=True)
    out = text
    for e in entities:
        out = out[:e["start"]] + f"[REDACTED_{e['type']}]" + out[e["end"]:]
    return out
