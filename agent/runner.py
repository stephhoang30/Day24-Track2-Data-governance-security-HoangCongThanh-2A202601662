"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành >=2 run riêng biệt — KHÔNG run nào cầm cả 3
chân của trifecta cùng lúc:

    Run A: search_docs (untrusted content). KHÔNG read_customer, KHÔNG http_post.
    Run B: read_customer (private data). CHỈ nhận input TYPED, ĐÃ SANITIZE từ
           Run A (list[int] ticket_id trích từ TÊN FILE), KHÔNG bao giờ nhận
           nguyên văn text document. Egress bị tắt ở run này.

Nguồn tin cậy để map ticket_id -> customer_id là `related_tickets` trong
data/customers.json, KHÔNG phải customer_id attacker nhúng trong nội dung.

Vì sao chống được biến thể 5 (không dấu / lookalike): Run B không ĐỌC free
text để quyết định gọi ai, nên việc attacker viết lại chỉ thị kiểu gì cũng
vô nghĩa — đây là containment (kiến trúc), khác mitigation (bộ lọc chuỗi).

Mọi lần gọi tool (allow HAY deny):
  1. Đi qua agent.policy.check() TRƯỚC khi tool chạy.
  2. Ghi vào ledger qua agent.ledger.append() — cả khi deny.
Nếu policy deny -> KHÔNG gọi tool đó.

Interface: handle(message, llm, log_dir=None) -> str
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, tools
from agent.policy import PolicyContext, check

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
CUSTOMERS_FILE = DATA_DIR / "customers.json"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-governed-agent"
_TICKET_ID_RE = re.compile(r"ticket-0*(\d+)", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _args_hash(*parts) -> str:
    payload = json.dumps(parts, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _ledger_path(log_dir: Path | None) -> Path:
    if log_dir is None:
        return DEFAULT_LEDGER_PATH
    return Path(log_dir) / "ledger.jsonl"


def _record(ledger_path, *, run_id, tool, args_hash, classification, ctx):
    """Chạy PEP cho 1 tool call rồi ghi ledger. Trả về (allow, reason).

    Đây là chỗ DUY NHẤT quyết định allow/deny + ghi audit, nên không có
    tool call nào lọt ra ngoài mà không có 1 dòng ledger kèm reason."""
    allow, reason = check(ctx)
    ledger.append(
        {
            "ts": _now(),
            "agent_id": AGENT_ID,
            "run_id": run_id,
            "agent_owner": run_id,          # định danh run gọi tool (ASI03)
            "tool": tool,
            "args_hash": args_hash,
            "classification": classification,
            "delegation_depth": ctx.delegation_depth,
            "egress_enabled": ctx.egress_enabled,
            "purpose": ctx.request_purpose,
            "decision": "allow" if allow else "deny",
            "reason": reason,               # KHÔNG BAO GIỜ rỗng (xem policy.py)
        },
        ledger_path,
    )
    return allow, reason


def _ticket_ids_from_docs(docs: list[dict]) -> list[int]:
    """Trích ticket_id từ TÊN FILE (typed, đã sanitize) — KHÔNG từ nội dung.
    'ticket-007.md' -> 7, 'ticket-904b.md' -> 904."""
    ids: list[int] = []
    for d in docs:
        m = _TICKET_ID_RE.search(d.get("id", ""))
        if m:
            ids.append(int(m.group(1)))
    return sorted(set(ids))


def _build_ticket_to_customer() -> dict[int, str]:
    """NGUỒN TIN CẬY: ticket_id -> customer_id qua related_tickets."""
    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    mapping: dict[int, str] = {}
    for c in customers:
        for t in c.get("related_tickets", []):
            mapping[int(t)] = c["customer_id"]
    return mapping


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = _ledger_path(log_dir)
    trace = uuid.uuid4().hex[:8]
    run_a = f"{trace}-run-a"
    run_b = f"{trace}-run-b"
    run_egress = f"{trace}-run-egress"

    # ---- Run A: untrusted content. Egress TẮT. Không read_customer/http_post ----
    allow_a, _ = _record(
        ledger_path,
        run_id=run_a,
        tool="search_docs",
        args_hash=_args_hash("search_docs", message),
        classification="internal",
        ctx=PolicyContext("internal", "summarize-tickets", run_a, 0, egress_enabled=False),
    )
    docs = tools.search_docs(message) if allow_a else []

    ticket_ids = _ticket_ids_from_docs(docs)

    # find_injection chỉ để GHI LOG (bằng chứng có lure), KHÔNG dùng
    # customer_ids / target_url của nó để quyết định bất cứ điều gì.
    injection = llm.find_injection("\n\n".join(d["text"] for d in docs)) if docs else None

    # ---- Run B: private data. Egress TẮT. customer_id suy từ ticket_id (typed) ----
    ticket_to_customer = _build_ticket_to_customer()
    customer_ids: list[str] = []
    for tid in ticket_ids:
        cid = ticket_to_customer.get(tid)
        if cid and cid not in customer_ids:
            customer_ids.append(cid)

    for cid in customer_ids:
        allow_b, _ = _record(
            ledger_path,
            run_id=run_b,
            tool="read_customer",
            args_hash=_args_hash("read_customer", cid),
            classification="restricted",
            ctx=PolicyContext("restricted", "summarize-tickets", run_b, 1, egress_enabled=False),
        )
        if allow_b:
            try:
                tools.read_customer(cid)      # đọc để phục vụ ticket hợp lệ
            except tools.ToolError:
                continue

    # ---- Egress: chỉ được THỬ khi có lure đòi exfil; PEP sẽ DENY ----
    # Đây là chân thứ 3 của trifecta. Dữ liệu restricted + egress bật ->
    # policy Rule 1 chặn TRƯỚC khi http_post chạy. Không có PII nào được
    # dựng vào body; ledger chỉ ghi args_hash (không phải giá trị thật).
    if injection is not None:
        target = injection.target_url
        allow_egress, _ = _record(
            ledger_path,
            run_id=run_egress,
            tool="http_post",
            args_hash=_args_hash("http_post", target, sorted(customer_ids)),
            classification="restricted",
            ctx=PolicyContext("restricted", "exfil-from-injection", run_egress, 1, egress_enabled=True),
        )
        if allow_egress:
            # Không bao giờ vào nhánh này với ruleset hiện tại — nhưng nếu ai
            # nới policy sai, allowlist tool vẫn là hàng rào cuối (localhost).
            tools.http_post(target, {"blocked": True})

    return llm.summarize(docs)
