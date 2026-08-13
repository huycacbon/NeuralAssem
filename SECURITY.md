# Security Policy

*(Tiếng Việt bên dưới / Vietnamese below)*

## Reporting a vulnerability

Please report security issues privately — do **not** open a public GitHub issue for anything that
could be actively exploited.

- Preferred: GitHub → this repo → **Security** tab → **Report a vulnerability** (private security
  advisory).
- Alternative: open a regular issue titled `[security] <short description>` with no exploit
  details, and wait for a maintainer to follow up privately before disclosing more.

Please include: what you did, what you expected, what happened instead, and — for anything in
`backend/app/dynamic/` — whether a real debug target (VM or local-launch) was involved.

There is no bug bounty; this is a personal/community project maintained on a best-effort basis.

## Scope

**In scope** (please report):

- Any way the **static analyzer** (`backend/app/`, minus `app/dynamic/`) executes, spawns, or
  otherwise runs the uploaded sample — this breaks its core, test-enforced invariant
  (`test_sample_is_never_executed`, README §10) and is treated as a critical bug.
- Path traversal, SSRF, arbitrary file read/write, or any other request that escapes the intended
  temp-file/analysis sandbox via the static analyzer's own code paths.
- A `backend/app/dynamic/` COM vtable call (`backend/app/dynamic/debug_bridge/client.py`) that
  reads/writes memory outside the values its own docstring describes, crashes the analyst's own
  process, or otherwise misbehaves beyond "the debug session itself failed with an error" — see
  "Known, accepted risk" below for what this does *not* include.

**Out of scope** (working as designed, not a vulnerability):

- The Debug feature's **"run directly on this machine"** mode executing the file it was explicitly
  told to execute. This is a deliberate, documented, user-initiated exception to the "never
  executes" rule (README §10, §15) — see "Known, accepted risk" below.
- Denial-of-service via a very large or very slow-to-analyse PE file (there are size/timeout caps,
  but this project has no uptime/availability guarantee to defend).
- Anything requiring the attacker to already control the machine the app runs on (this is a local
  analysis tool, not a network service with a trust boundary between users).

## Known, accepted risk — read before using the Debug feature

This tool has one deliberate, documented exception to "the sample is never executed":

**Debug → "Run directly on this machine"** makes the app itself execute a file (either a path you
type, or the exact file you just uploaded) directly on the machine running the app, with **no
sandbox, no isolation**. This is not a bug — it is a debugger feature the user explicitly opts
into, confirmed by a warning shown every time before use.

**Only use this mode on files you already trust** (e.g. your own code). **For any unidentified or
suspicious sample, use the Remote mode instead** (connect to a `dbgsrv` running in a VM you
control) — or, more simply: **run this whole tool inside an isolated VM** whenever you intend to
analyse real, untrusted malware, regardless of which debug mode you use. Static analysis
(sections 1–14) never executes anything either way, but a VM is still the right place to do this
kind of work — see README §10's note on parser-level risk even without execution.

Separately: most of the dynamic-analysis module's low-level Windows debugging code
(`backend/app/dynamic/debug_bridge/client.py`) talks to `dbgeng.dll` through hand-counted COM
vtable calls, and several capabilities (live disassembly, register/flag writes, memory dumps, x64
support) are implemented but **not yet verified against a real live target** — this is stated
explicitly in that file's own docstrings. A wrong call here is a memory-safety issue in the
analyst's *own* process, not a remote attack surface, but it is a real reason to expect rough edges
and to run this inside a VM regardless of which debug mode is in use.

## Supported versions

Single rolling `main` branch, no maintained older versions. Fixes land as new commits; there is no
backport policy at this project's current size.

---

# Chính sách bảo mật (Tiếng Việt)

## Báo lỗi bảo mật

Vui lòng báo **riêng tư** — **không** mở issue công khai cho bất kỳ lỗi nào có thể bị khai thác
thực sự.

- Ưu tiên: GitHub → repo này → tab **Security** → **Report a vulnerability** (advisory riêng tư).
- Cách khác: mở issue thường với tiêu đề `[security] <mô tả ngắn>`, không nêu chi tiết cách khai
  thác, chờ maintainer liên hệ riêng trước khi công khai thêm.

Vui lòng cho biết: đã làm gì, kỳ vọng gì, thực tế xảy ra gì, và — nếu liên quan tới
`backend/app/dynamic/` — có target debug thật (VM hay local-launch) hay không.

Không có bug bounty; đây là dự án cá nhân/cộng đồng, bảo trì trên tinh thần best-effort.

## Phạm vi

**Trong phạm vi** (nên báo):

- Bất kỳ cách nào khiến **static analyzer** (`backend/app/`, trừ `app/dynamic/`) thực thi/chạy file
  mẫu — vi phạm bất biến cốt lõi đã được test khóa cứng
  (`test_sample_is_never_executed`, README mục 10), coi là bug nghiêm trọng.
- Path traversal, SSRF, đọc/ghi file tùy ý, hoặc bất kỳ cách nào thoát khỏi sandbox
  temp-file/phân tích qua chính code của static analyzer.
- Một lời gọi COM vtable trong `backend/app/dynamic/` (`debug_bridge/client.py`) đọc/ghi sai vùng
  nhớ so với docstring mô tả, crash chính process của người phân tích, hoặc có hành vi bất thường
  vượt quá "phiên debug tự báo lỗi" — xem "Rủi ro đã biết, đã chấp nhận" bên dưới để rõ cái gì
  *không* tính vào đây.

**Ngoài phạm vi** (thiết kế có chủ đích, không phải lỗ hổng):

- Chế độ **"Chạy trực tiếp trên máy này"** của tính năng Debug thực thi đúng file được yêu cầu.
  Đây là ngoại lệ có chủ đích, đã ghi tài liệu, người dùng tự chọn (README mục 10, mục 15) — xem
  "Rủi ro đã biết, đã chấp nhận" bên dưới.
- DoS bằng file PE rất lớn hoặc rất chậm phân tích (đã có giới hạn size/timeout, nhưng dự án không
  cam kết uptime/availability).
- Bất kỳ điều gì yêu cầu kẻ tấn công đã kiểm soát sẵn máy đang chạy app (đây là tool phân tích cục
  bộ, không phải network service có ranh giới tin cậy giữa nhiều người dùng).

## Rủi ro đã biết, đã chấp nhận — đọc trước khi dùng tính năng Debug

Tool có đúng một ngoại lệ có chủ đích với nguyên tắc "không bao giờ thực thi sample":

**Debug → "Chạy trực tiếp trên máy này"** khiến app tự thực thi một file (đường dẫn tự gõ, hoặc
đúng file vừa upload) ngay trên máy đang chạy app, **không sandbox, không cách ly**. Đây không phải
bug — là tính năng debugger người dùng chủ động bật, có cảnh báo hiện lại mỗi lần trước khi dùng.

**Chỉ dùng chế độ này cho file bạn đã tin tưởng** (vd. code của chính bạn). **Với mẫu chưa xác
định/nghi ngờ, dùng chế độ Remote** (kết nối tới `dbgsrv` chạy trong VM bạn tự kiểm soát) — hoặc,
đơn giản hơn: **chạy cả tool trong một VM cách ly** bất cứ khi nào định phân tích mã độc thật, bất
kể dùng chế độ debug nào. Phân tích tĩnh (mục 1–14) không bao giờ thực thi gì cả dù thế nào, nhưng
VM vẫn là nơi đúng để làm việc này — xem ghi chú ở README mục 10 về rủi ro ở tầng parser dù không
thực thi.

Ngoài ra: phần lớn code debug Windows cấp thấp (`backend/app/dynamic/debug_bridge/client.py`) gọi
thẳng `dbgeng.dll` qua COM vtable đếm bằng tay, và một số khả năng (disassemble trực tiếp, ghi
register/cờ, dump memory, hỗ trợ x64) đã cài đặt nhưng **chưa được kiểm chứng trên target thật** —
ghi rõ trong chính docstring của file đó. Gọi sai ở đây là vấn đề an toàn bộ nhớ trong process của
*chính người phân tích*, không phải bề mặt tấn công từ xa, nhưng là lý do thật để lường trước còn
gồ ghề và nên chạy trong VM bất kể dùng chế độ debug nào.

## Phiên bản được hỗ trợ

Một nhánh `main` duy nhất, không duy trì phiên bản cũ. Fix được đưa vào commit mới; dự án ở quy mô
hiện tại chưa có chính sách backport.
