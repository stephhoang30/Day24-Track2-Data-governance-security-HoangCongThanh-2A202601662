"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Thiết kế: ruleset có thứ tự, fail-closed. Mỗi nhánh trả về reason mô tả
được ĐỦ để dựng lại quyết định từ ledger mà không cần đọc lại code — đó là
lý do reason nhét cả purpose/owner/egress vào, không phải một chữ "ok".
"""
from __future__ import annotations

from dataclasses import dataclass

_ALLOWED_CLASSIFICATIONS = ("public", "internal", "restricted")
_MAX_DELEGATION_DEPTH = 3


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    c = context.data_classification
    owner = context.agent_owner
    purpose = context.request_purpose

    # Rule 1 (TỐI THIỂU, bắt buộc): dữ liệu restricted KHÔNG được rời hệ
    # thống. Đây là chân "exfil" của trifecta bị cắt ở tầng policy.
    if c == "restricted" and context.egress_enabled:
        return (
            False,
            f"deny: du lieu 'restricted' khong duoc egress "
            f"(egress_enabled=True, purpose={purpose!r}, owner={owner!r}, "
            f"delegation_depth={context.delegation_depth})",
        )

    # Rule 2: delegation quá sâu -> deny (chống privilege abuse ASI03: một
    # agent gọi agent gọi agent... không được leo thang vô hạn).
    if context.delegation_depth > _MAX_DELEGATION_DEPTH:
        return (
            False,
            f"deny: delegation_depth={context.delegation_depth} vuot nguong "
            f"{_MAX_DELEGATION_DEPTH} (owner={owner!r})",
        )

    # Rule 3: restricted NHƯNG egress đã tắt -> cho phép đọc nội bộ. Đây là
    # Run B trong trifecta split: được đọc private data, nhưng không có
    # đường ra network nên đọc xong cũng không exfil được.
    if c == "restricted":
        return (
            True,
            f"allow: doc du lieu 'restricted' noi bo, egress da tat "
            f"(owner={owner!r}, purpose={purpose!r})",
        )

    # Rule 4: public / internal -> cho phép (kể cả khi egress bật, vì dữ
    # liệu không nhạy cảm).
    if c in _ALLOWED_CLASSIFICATIONS:
        return (
            True,
            f"allow: du lieu '{c}' khong nhay cam "
            f"(egress_enabled={context.egress_enabled}, purpose={purpose!r}, owner={owner!r})",
        )

    # Default fail-closed: classification lạ -> từ chối, không đoán.
    return (
        False,
        f"deny: classification {c!r} khong thuoc {_ALLOWED_CLASSIFICATIONS} "
        f"(fail-closed, owner={owner!r})",
    )
