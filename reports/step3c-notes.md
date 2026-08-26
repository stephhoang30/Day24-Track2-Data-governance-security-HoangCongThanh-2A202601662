# Bước 3c — vì sao filter chuỗi là mitigation, split là containment

Guide §3c yêu cầu: thử một filter chuỗi trước, rồi tự phá nó bằng biến thể 5.

## Thí nghiệm

Giả sử ở `runner.py` mình chặn bằng một naive string filter, grep các cụm
lệnh **có dấu**:

```python
NAIVE = ["hãy gọi", "hệ thống", "chỉ thị từ admin"]
if any(t in doc_text for t in NAIVE):
    block()
```

Kết quả (chạy thật, xem lệnh trong lịch sử Bước 3c):

| Biến thể | Filter chuỗi | Vì sao |
|---|---|---|
| 3 — giả mạo thẩm quyền (có dấu) | **BLOCK** (`'hãy gọi'`) | viết đúng chính tả có dấu |
| 5 — không dấu / teencode | **LỌT** (`[]`) | `"hay g0i"`, `"he thong"` không khớp cụm có dấu |

Filter chuỗi bị biến thể 5 phá đúng như dự đoán. Muốn vá, mình lại phải thêm
`"hay goi"`, `"hay g0i"`, `"h4y g0i"`, ... — một cuộc rượt đuổi vô tận với
attacker, người luôn có thêm một cách viết lại nữa.

## Containment (cách đang dùng)

`agent/runner.py` KHÔNG đọc free text để quyết định gọi ai. Run B suy
`customer_id` từ `ticket_id` (trích từ **tên file**) → `related_tickets`
trong `data/customers.json` (nguồn tin cậy). Hệ quả:

- Attacker viết lại chỉ thị kiểu gì (có dấu, không dấu, teencode, homoglyph,
  chia 2 file) cũng **không đổi** được `related_tickets` — nên không đổi
  được Run B đọc ai.
- Khách chỉ được nhắc trong free text (vd `KH-000777`, `related_tickets=[]`)
  **không bao giờ bị đọc** — `tests/test_split.py` chứng minh điều này.
- Chân exfil (`http_post`) bị `policy.check()` deny ở tầng PEP
  (restricted + egress) TRƯỚC khi tool chạy, có 1 dòng `decision=deny`
  trong ledger.

Containment không cần biết TOÀN BỘ cách viết lại của attacker; nó chỉ đảm
bảo run đọc private data không bao giờ đọc free text để hành động. Đó là
khác biệt cốt lõi giữa **mitigation** (bộ lọc, luôn có thể bị né) và
**containment** (kiến trúc, cắt hẳn đường đi).
