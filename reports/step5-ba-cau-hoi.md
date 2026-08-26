# Ba câu hỏi chốt buổi (Guide.md, cuối file)

Trả lời bằng code/log thật trong repo này, không nói chung chung.

---

## 1. Bạn đã bỏ chân nào của trifecta, và agent mất đi khả năng gì?

**Không xoá tool nào.** Cả 3 tool vẫn còn trong `agent/tools.py`. Cái bị bỏ
là **sự đồng thời**: không run nào cầm cả 3 chân nữa.

| Run | Chân được cầm | Chân bị lấy đi | Code |
|---|---|---|---|
| Run A | untrusted content (`search_docs`) | không private data, `egress_enabled=False` | `agent/runner.py:118-127` |
| Run B | private data (`read_customer`) | **không đọc free text**, `egress_enabled=False` | `agent/runner.py:135-155` |
| Run egress | đề xuất `http_post` | dữ liệu `restricted` → PEP **deny** trước khi tool chạy | `agent/runner.py:163-175`, `agent/policy.py:53-61` |

Chân bị cắt dứt khoát nhất là **exfil đối với run cầm private data**: Run B
đọc được `customers.json` nhưng không có đường ra network, nên đọc xong cũng
không gửi đi đâu được.

### Agent mất khả năng gì (chi phí thật, không tô hồng)

1. **Mất khả năng làm theo chỉ thị nằm trong document.** Kể cả chỉ thị
   *thật* từ khách. Nếu khách viết trong ticket "gửi sao kê của tôi tới
   URL X", agent bây giờ **không làm được** — nó không còn đọc free text để
   quyết định hành động. Đây là tiện ích bị mất có thật, không phải chỉ mất
   đường tấn công.
2. **Mất khả năng phục vụ khách không có trong `related_tickets`.** Run B
   chỉ với tới customer qua `ticket_id → related_tickets`
   (`agent/runner.py:101-113`). Ticket mới chưa được map, hoặc mapping cũ/sai
   → agent **không đọc được** hồ sơ khách đó. Containment này đẩy gánh nặng
   sang việc phải giữ mapping tin cậy luôn đúng.
3. **Mất luôn egress hợp pháp của dữ liệu restricted.** Ruleset hiện tại
   deny *mọi* `restricted + egress` (`agent/policy.py:53`). Muốn có một
   luồng đối soát hợp lệ POST sang hệ thống nội bộ thì phải thêm rule
   allowlist theo `purpose` + đích đến — chưa có.
4. **Chi phí vận hành:** 1 yêu cầu → 3 run, 23 dòng ledger cho một câu hỏi
   (`reports/ledger.jsonl`).

### Rủi ro còn lại tự phát hiện

- **Over-collection:** query rộng khớp 46 ticket → Run B đọc **21** hồ sơ
  khách (`grep -c '"tool": "read_customer"' reports/ledger.jsonl` = 21).
  Đúng policy nhưng sai tinh thần data minimization: nên giới hạn theo
  ticket thực sự cần tóm tắt.
- **PII gate chưa nằm trong đường chạy** — xem câu 2.

---

## 2. Nếu attacker có quyền ghi vào `corpus/`, control nào của bạn còn đứng vững?

Đây đúng là mô hình đe doạ của bài lab: attacker **đã** ghi được vào
`corpus/` (5 biến thể đều là file trong đó).

### Còn đứng vững

| Control | Vì sao attacker ghi `corpus/` không phá được |
|---|---|
| **Trifecta split** (`agent/runner.py:135-155`) | `customer_id` suy từ `related_tickets` trong `data/customers.json` — file attacker **không** ghi được. Viết lại chỉ thị kiểu gì (không dấu, teencode, chia 2 file) cũng không đổi được mapping. Bằng chứng: `tests/test_split.py` PASS, `KH-000777` không bao giờ bị đọc. |
| **PEP deny egress** (`agent/policy.py:53-61`) | Quyết định dựa trên `classification` + `egress_enabled` của *run*, không dựa trên nội dung document. Mạo danh "System note / admin / DPO" (biến thể 3) không đổi được 2 giá trị đó. |
| **Audit ledger** (`agent/ledger.py:60-95`) | Ledger nằm ở `reports/ledger.jsonl`, ngoài `corpus/`. Attacker chỉ ghi được `corpus/` thì không sửa được ledger; mà sửa được cũng gãy hash chain (`verify()` → False). |

### KHÔNG đứng vững / phải nói thẳng

1. **Attacker chọn được TÊN FILE, mà tên file là input tin cậy của Run B.**
   `_ticket_ids_from_docs` (`agent/runner.py:90-99`) trích `ticket_id` từ tên
   file. Attacker tạo `corpus/ticket-014.md` → ép agent đọc hồ sơ khách sở
   hữu ticket 14 (`KH-000001`). Tức là attacker **điều khiển được agent đọc
   ai**, miễn khách đó có ít nhất 1 ticket trong `related_tickets`.
   *Chặn được gì:* dữ liệu đọc ra vẫn **không ra ngoài** (egress deny), và
   khách có `related_tickets=[]` vẫn ngoài tầm với. *Còn hở:* việc đọc
   trái mục đích vẫn xảy ra và chỉ bị *ghi nhận*, không bị *ngăn*.
2. **PII gate `agent/pii.py` chưa được nối vào `runner.py`.**
   `grep -n pii agent/runner.py` → không có dòng nào. `pii.py` đã viết và đo
   (precision=1.000, recall=1.000 ở `tests/test_pii.py`) nhưng **không nằm
   trong đường chạy** của agent: text từ `corpus/` vào context vẫn là text
   thô. Đây đúng là kiểu "control có trên giấy, không có trong production"
   mà buổi học phê phán — ghi ra đây thay vì để nó trông như đang bảo vệ
   pipeline. Sửa: gọi `pii.redact()` lên `d["text"]` ngay sau `search_docs`
   (`agent/runner.py:127`), trước khi ghép vào context.
3. **Allowlist `localhost:9999`** (`agent/tools.py:76-82`) không phải control
   — docstring của chính nó nói vậy. Nó chỉ giữ cho bài lab không POST ra
   Internet thật.

---

## 3. Regulator hỏi "chứng minh dữ liệu khách hàng chưa từng ra khỏi hệ thống" — bạn mở file nào ra?

**Mở `reports/ledger.jsonl`.**

```bash
# 1) Toàn vẹn: chưa ai sửa/xoá/chèn dòng nào
python -c "from agent import ledger; from pathlib import Path; \
print(ledger.verify(Path('reports/ledger.jsonl')))"        # True

# 2) Mọi tool call đều có quyết định + lý do (không dòng nào khuyết)
python -c "import json; L=[json.loads(l) for l in open('reports/ledger.jsonl')]; \
print(len(L), all(e['decision'] and e['reason'] for e in L))"   # 23 True

# 3) Lần duy nhất có ai đó đòi gửi dữ liệu ra ngoài — và nó bị chặn
grep '\"tool\": \"http_post\"' reports/ledger.jsonl
```

Dòng đó (dòng 23) nói đủ mọi thứ regulator cần, **trước** khi tool chạy:

```
"tool": "http_post", "classification": "restricted", "egress_enabled": true,
"decision": "deny",
"reason": "deny: du lieu 'restricted' khong duoc egress (egress_enabled=True,
           purpose='exfil-from-injection', owner='...-run-egress', delegation_depth=1)"
```

Ba file bổ trợ:

| File | Chứng minh điều gì |
|---|---|
| `reports/attack-after.log` | **0 byte** — phía *nhận* không nhận được gì. Evidence độc lập với agent. |
| `reports/attack-before.log` | 298 byte có `cccd/phone/bank_account` của `KH-000999` — chứng minh phép đo có độ nhạy (nếu rò rỉ, log này *sẽ* bắt được). |
| `tests/test_injection.py`, `tests/test_split.py` | Tái lập được: 5/5 biến thể bị chặn, không đọc khách do attacker chỉ định. |

### Giới hạn của bằng chứng này (nói trước, đừng để regulator tự tìm ra)

- Ledger chứng minh **PEP đã quyết định gì**, không chứng minh **OS đã gửi
  gói tin nào**. Câu khẳng định đúng phạm vi là: *"không tool call nào đi qua
  `runner.handle` mang dữ liệu restricted ra ngoài"*. Muốn mạnh hơn phải có
  thêm log egress ở tầng network/proxy.
- Chỉ những call đi qua `_record()` (`agent/runner.py:64-88`) mới có vết. Ai
  gọi thẳng `tools.http_post()` ngoài runner sẽ **không** để lại dòng nào —
  đây là lý do trong hệ thống thật, PEP phải nằm ở tầng không bypass được
  (sidecar/proxy), không phải một hàm Python người ta có thể vòng qua.
- Ledger cố ý **không** lưu PII (chỉ `args_hash`) — tốt cho quyền xoá
  (Luật 91/2025) nhưng đồng nghĩa: không dùng ledger để chứng minh *giá trị
  cụ thể nào* đã bị đọc, chỉ chứng minh *đã đọc/không gửi*.
