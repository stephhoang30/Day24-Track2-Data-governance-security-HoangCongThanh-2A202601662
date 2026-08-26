# DPIA-lite (1 trang)

Phạm vi: agent hỗ trợ khách hàng ở Lab 24, xử lý yêu cầu "Tổng hợp các
ticket còn mở tuần này" bằng 3 tool (`search_docs`, `read_customer`,
`http_post`). Chấm bằng `--mock` (deterministic, không gọi API ngoài).

## 1. Dữ liệu gì

| Nguồn | Tool chạm tới | Loại dữ liệu |
|---|---|---|
| `corpus/*.md` (40 ticket + lure) | `search_docs` (Run A) | Nội dung ticket — **untrusted**, có thể chứa PII synthetic (SĐT, STK trong body ticket) và cả payload injection. |
| `data/customers.json` | `read_customer` (Run B) | **Dữ liệu cá nhân** khách hàng (synthetic): `name`, `cccd` (12 số), `phone`, `bank_account`, `email`, `related_tickets`. Đây là dữ liệu nhạy cảm nhất (CCCD ~ định danh công dân). |

Toàn bộ là dữ liệu **synthetic** (README, Quy tắc an toàn) — không có dữ liệu
cá nhân thật của bất kỳ ai. PII gate `agent/pii.py` nhận diện 4 loại
(`VN_CCCD/VN_PHONE/VN_BANK_ACCOUNT/EMAIL`, recall=1.00 trên test set) để
redact trước khi đưa vào nơi có thể rò rỉ.

## 2. Mục đích gì

Trả lời yêu cầu nghiệp vụ "tổng hợp ticket còn mở" cho nhân viên hỗ trợ.
Agent cần:
- đọc `corpus/` để biết ticket nào khớp (Run A);
- đọc `customers.json` để gắn ticket với khách hàng phục vụ tóm tắt (Run B).

Mục đích **hợp lệ** dừng ở đọc + tóm tắt nội bộ. Việc `http_post` dữ liệu
khách ra ngoài **không** nằm trong mục đích này — nó chỉ xuất hiện khi bị
prompt injection lèo lái (goal hijack, ASI01), và bị chặn.

## 3. Chảy đi đâu

| Điểm đến | Có PII đi qua? | Control |
|---|---|---|
| Context của agent (bộ nhớ tiến trình) | Có (Run B đọc record) | Trifecta split: chỉ Run B (egress **tắt**) chạm private data — `agent/runner.py:135-155`. |
| `reports/ledger.jsonl` (audit nội bộ) | **Không** — chỉ `args_hash` + `reason` | `agent/ledger.py:43-46`; kiểm chứng "PII thô trong ledger: KHÔNG có" (Bước 4). |
| Sink `localhost:9999` (đích exfil của attacker) | **Không** sau contain | PEP deny egress `agent/policy.py:53-61`; bằng chứng `reports/attack-after.log` **rỗng** (trước contain: `reports/attack-before.log` có CCCD/STK). |
| **API model provider** (nếu chạy `--model claude-...`) | **Có** — text ticket + record được gửi tới Anthropic API | Mặc định lab dùng `--mock` → **KHÔNG** rời máy. Chỉ khi ai đó tự thêm `--model` thì dữ liệu mới ra ngoài. |

### Chuyển dữ liệu xuyên biên giới (NĐ 356/2025)

- Với `--mock` (đường mặc định, dùng để chấm): **không** có chuyển dữ liệu
  xuyên biên giới. Không request nào rời máy.
- Với `--model claude-...`: gọi Anthropic API (`agent/llm.py:119-133`,
  hàm `RealLLM.summarize`), server ở nước ngoài → **là** chuyển dữ liệu cá
  nhân xuyên biên giới. Nếu triển khai thật, đây là hoạt động phải lập hồ sơ
  đánh giá tác động và lưu 60 ngày theo NĐ 356/2025 trước khi chuyển.
- Egress control có sẵn: `http_post` bị hard-allowlist `localhost:9999`
  (`agent/tools.py:76-82`) + PEP deny khi `restricted + egress`
  (`agent/policy.py:53-61`) — nhưng lưu ý các control này **không** chặn
  đường LLM API; kiểm soát đường đó là bằng cách **không bật `--model`** khi
  không cần, và coi mỗi lần bật là một sự kiện chuyển dữ liệu phải khai báo.

## Rủi ro còn lại

- Chưa có **delete cascade** (quyền xoá — Luật 91/2025): xem stretch #3.
- PII gate là regex-first, có thể sót định dạng lạ ngoài test set (chấp nhận
  được ở phạm vi lab; spaCy/transformers là stretch).
- Đường `--model` chưa có DLP/redact tự động trước khi gửi API — hiện dựa
  vào kỷ luật "mặc định `--mock`".
