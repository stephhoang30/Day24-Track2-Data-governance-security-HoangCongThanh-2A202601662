# Compliance mapping

Evidence là **đường dẫn file/dòng thật** trong repo này (không phải mô tả
chung). Tái lập bằng `--mock` + `pytest` — xem `Guide.md` Bước 4, `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | **Chưa implement delete cascade** (stretch #3, Guide). Hiện chỉ có nền tảng: dữ liệu subject tập trung ở một store duy nhất `data/customers.json`, ledger tách khỏi PII nên xoá subject không phá được audit trail. | `data/customers.json` (một nguồn); `agent/ledger.py:43-46` (ledger chỉ lưu `args_hash`, không lưu PII → xoá subject vẫn giữ ledger nguyên vẹn). Kiểm chứng không PII trong ledger: mục "PII thô trong ledger.jsonl: KHÔNG có" ở Bước 4. |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call: liệt kê rõ khi nào dữ liệu ra khỏi biên giới (chỉ khi dùng `--model`, mặc định `--mock` không gọi API ngoài). | `reports/dpia-lite.md` §3 (mục "Chảy đi đâu"); egress control: `agent/policy.py:53-61` + `agent/runner.py:163-175`. |
| ASI03 — privilege abuse | Per-run identity + least-privilege: mỗi run có `run_id`/`agent_owner` riêng ghi vào ledger; Run B đọc private data nhưng `egress_enabled=False`; guard `delegation_depth > 3`. | `agent/runner.py:75` (field `agent_owner` = run_id per-run); `agent/runner.py:147` (Run B `PolicyContext(..., egress_enabled=False)`); `agent/policy.py:63-67` (deny khi delegation quá sâu). Ledger thực: `reports/ledger.jsonl` (mỗi dòng có `agent_owner`). |
| ASI01 — goal hijack | Trifecta split: Run B suy `customer_id` từ `ticket_id`→`related_tickets` (nguồn tin cậy), không đọc free text của attacker; egress bị PEP deny. | `agent/runner.py:101-113` (`_build_ticket_to_customer`, map tin cậy) + `agent/runner.py:135-155` (Run B); bằng chứng chặn: `reports/attack-after.log` (rỗng) và `tests/test_split.py` PASS. |
| ISO 42001 Clause 5-6 | Policy-as-code có review: chính sách là code (`agent/policy.py`), thay đổi đi qua git (review được, có lịch sử). | `git log --oneline -- agent/policy.py` → commit `627932f` "step 3b: agent/policy.py — PEP tại tool call". Rule tối thiểu: `agent/policy.py:53-61`. |

## Cách tái lập evidence

```bash
python sink/sink.py --reset
pytest tests/test_injection.py -v          # 5/5 biến thể bị chặn
python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"
cat reports/attack-after.log               # RỖNG — không PII ra sink
grep '"decision": "deny"' reports/ledger.jsonl   # >=1 dòng deny http_post
python -c "from agent import ledger; from pathlib import Path; print(ledger.verify(Path('reports/ledger.jsonl')))"  # True
```
