"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash.
        Append 1 dòng JSON (utf-8, ensure_ascii=False), tạo file/thư mục cha
        nếu chưa có. Trả về dict đầy đủ đã ghi (gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        True nếu TẤT CẢ: mọi dòng có reason non-empty; prev_hash dòng n ==
        hash dòng n-1 (dòng đầu so với "0"*64); hash lưu khớp khi tính lại.
        False nếu bất kỳ dòng nào bị sửa/xoá/chèn, hoặc thiếu reason.

Vì sao tamper-evident: hash mỗi dòng phủ lên prev_hash, nên sửa 1 ký tự ở
dòng k làm hash(k) đổi -> prev_hash(k+1) không còn khớp -> verify() gãy tại
đó. Muốn giả mạo phải tính lại hash của MỌI dòng từ k tới cuối.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_ZERO_HASH = "0" * 64


def _canonical(payload: dict) -> str:
    """Chuỗi hoá tất định (sort_keys) để thứ tự field không đổi kết quả hash."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _hash_payload(payload: dict) -> str:
    """sha256 của payload (đã bỏ field 'hash' nếu có)."""
    body = {k: v for k, v in payload.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def _read_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = _read_lines(path)
    prev_hash = existing[-1]["hash"] if existing else _ZERO_HASH

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _hash_payload(record)  # phủ lên mọi field + prev_hash

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    path = Path(path)
    lines = _read_lines(path)

    expected_prev = _ZERO_HASH
    for entry in lines:
        # 1) reason non-empty (điều kiện trượt số 1 trong Rubric.md).
        if not entry.get("reason"):
            return False
        # 2) chuỗi hash liền mạch: prev_hash phải trỏ đúng dòng trước.
        if entry.get("prev_hash") != expected_prev:
            return False
        # 3) hash của dòng này phải khớp khi tính lại từ nội dung.
        stored = entry.get("hash")
        if stored != _hash_payload(entry):
            return False
        expected_prev = stored

    return True
