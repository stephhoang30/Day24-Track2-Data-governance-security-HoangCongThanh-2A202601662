# Bước 1 — Baseline: đọc `_naive_loop` trước khi tấn công

Setup đã verify (Bước 0): `python sink/sink.py` nghe ở `localhost:9999`,
`python -m agent.loop --mock "Tóm tắt ticket về hoá đơn"` trả về
`Đã tổng hợp 41 ticket (...)` — và **ngay ở smoke test này** `reports/sink.log`
đã có 1 dòng chứa CCCD/STK của `KH-000999`. Chưa tấn công gì cả, chỉ hỏi một
câu vô hại.

## Luồng của `agent/loop.py:_naive_loop` (dòng 27-54)

```
user message
   │
   ├─(1) tools.search_docs(message)          agent/loop.py:31   ← chân 1: untrusted content
   │        trả về TOÀN VĂN mọi file .md khớp (agent/tools.py:34-52)
   │
   ├─(2) llm.find_injection(combined_text)   agent/loop.py:34
   │        "bộ não" đọc text của attacker như một phần context
   │
   ├─(3) tools.read_customer(customer_id)    agent/loop.py:39   ← chân 2: private data
   │        customer_id lấy từ `injected.customer_ids`, tức là từ
   │        văn bản attacker viết (agent/llm.py:76)
   │
   └─(4) tools.http_post(injected.target_url, {...})  agent/loop.py:44  ← chân 3: exfil
            URL cũng lấy từ văn bản attacker viết (agent/llm.py:77-78)
```

Cả 3 chân của lethal trifecta nằm trong **một run duy nhất, một context duy
nhất**. Không có ranh giới nào giữa "dữ liệu đọc được" và "lệnh phải làm".

## 3 câu hỏi

### 1. Agent này có identity riêng không (per-run, per-agent id)?

**Không.** Không có dòng nào sinh ra `agent_id` hay `run_id`:

- `_naive_loop(message, llm)` (`agent/loop.py:27`) chỉ nhận message + llm,
  không có tham số identity, không tạo ra identity nào bên trong.
- 3 tool ở `agent/tools.py` (`search_docs:34`, `read_customer:55`,
  `http_post:68`) **không nhận tham số caller nào** — chúng không biết ai gọi.
- `agent/policy.py` có sẵn field `agent_owner` trong `PolicyContext`
  (`agent/policy.py:34`) nhưng `check()` chưa được implement và **không có
  chỗ nào trong `_naive_loop` gọi tới nó**.

Hệ quả: mọi run đều nặc danh và không phân biệt được với nhau. Không thể
trả lời "run nào đã đọc `KH-000999`", không thể set TTL, không thể revoke.
Đây đúng là ASI03 (privilege abuse) ở dạng thô nhất: quyền gắn vào *code*,
không gắn vào *danh tính*.

### 2. Ai quyết định nó được gọi `http_post`?

**Attacker — người ghi được vào `corpus/`.** Chuỗi quyết định:

- `agent/loop.py:35` — `if injected is not None:` là *toàn bộ* điều kiện để
  chạy nhánh exfil. Không có policy check, không có approval, không có
  allowlist purpose.
- `injected` sinh ra từ `llm.find_injection(combined_text)`
  (`agent/loop.py:34`), mà `combined_text` là nội dung file trong `corpus/`
  ghép lại (`agent/loop.py:32`).
- Cả **URL đích** (`agent/llm.py:77-78`) lẫn **danh sách customer_id**
  (`agent/llm.py:76`) đều được trích từ chính văn bản đó.

Cái duy nhất còn chặn là allowlist hard-code host/port trong
`agent/tools.py:76-82`. Nhưng docstring của chính hàm đó
(`agent/tools.py:71-75`) nói rõ: đó là *hàng rào an toàn của bài lab* để
không ai vô tình POST ra Internet thật — **không phải** security control để
dựa vào. Nếu URL trong document là `http://localhost:9999/bất-kỳ-đâu` thì
nó đi qua thoải mái.

### 3. Nếu nó gửi sai dữ liệu ra ngoài, bạn biết bằng cách nào?

**Chỉ biết nhờ log của *bên nhận*, tức là log của attacker.**

- `reports/sink.log` do `sink/sink.py:46-47` ghi — đó là server đích, không
  phải agent. Trong đời thật server đó là của attacker → mình không có gì hết.
- `_naive_loop` **không ghi bất kỳ dòng log nào**: không có `ledger.append`,
  không `decision`, không `reason`, không `args_hash`. `agent/ledger.py:39`
  vẫn là `raise NotImplementedError`.
- Tệ hơn: lỗi bị nuốt im lặng. `agent/loop.py:40-41` bắt `tools.ToolError`
  rồi `continue` — đọc nhầm 10 customer_id không tồn tại cũng không để lại vết.
- Giá trị trả về cho người dùng (`agent/loop.py:54`, `llm.summarize(docs)`)
  chỉ liệt kê tên file. Người dùng nhìn output **không thấy gì bất thường** —
  đúng như smoke test ở trên: câu trả lời trông hoàn toàn bình thường trong
  khi PII đã ra khỏi hệ thống.

Nói ngắn gọn: nếu regulator hỏi "chứng minh dữ liệu khách chưa từng ra khỏi
hệ thống", ở baseline này mình **không có file nào để mở ra**. Đó là lý do
Bước 3d (ledger) tồn tại.

## 3 lớp đang thiếu (chính là Bước 3)

| Thiếu | Hậu quả quan sát được | Sẽ vá ở |
|---|---|---|
| PII gate trước ingestion | PII thô đi thẳng vào context | Bước 3a `agent/pii.py` |
| PEP tại tool call | ai cũng gọi được `http_post` | Bước 3b `agent/policy.py` |
| Trifecta split | 1 run cầm cả 3 chân | Bước 3c `agent/runner.py` |
| Audit ledger | không có evidence phía mình | Bước 3d `agent/ledger.py` |
