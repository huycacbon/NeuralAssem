# Test fixtures (benign)

Bộ PE **lành tính** để test Binary Graph Analyzer. Mỗi file cố tình dùng
**kỹ thuật *trông giống* mã độc** (gọi/tham chiếu các API đáng ngờ, nhúng chuỗi
đáng ngờ) để kích hoạt import extractor, API graph, string extractor và risk
scorer — nhưng **không thực hiện bất kỳ hành vi độc hại nào**.

> ⚠️ **Đây KHÔNG phải mã độc.** Không có injection, không kết nối mạng, không ghi
> registry/persistence, không phá file. Mọi lệnh nguy hiểm nằm sau nhánh
> `if (argc > 100000)` (không bao giờ chạy) và, kể cả trong nhánh đó, chỉ nhắm
> vào **chính tiến trình này**. Các API chỉ cần *có mặt trong import table* để
> phân tích **tĩnh** nhìn thấy — chúng không được thực thi. Xem header từng file
> trong `src/`.
>
> Dù vậy, thói quen tốt: phân tích mẫu thật trong máy ảo cách ly. App này không
> chạy mẫu, nhưng bạn nên tự tạo thói quen đó với mẫu thật.

## Danh sách

| File | Nguồn | Test cái gì | Kết quả kỳ vọng (đã kiểm chứng) |
|---|---|---|---|
| `01_simple_debug.exe` | `src/simple.c` `/Od /Zi` | Build **debug** không tối ưu | ~3400 function, ~34k block (CRT tĩnh chưa tối ưu) |
| `02_simple_release.exe` | `src/simple.c` `/O2` | Build **release** — *cùng source với 01* | ~660 function, ~7.7k block. So sánh 01↔02 để thấy tối ưu định hình lại CFG |
| `03_branch_loop.exe` | `src/branch_loop.c` `/O2` | CFG dày: vòng lặp lồng, switch, điều kiện | CFG nhiều block với đủ edge `TRUE/FALSE/JUMP/FALLTHROUGH` và back-edge |
| `04_imports.exe` | `src/imports.c` `/O2` | Import extractor + API graph + risk theo API | **8 capability**: filesystem, memory, persistence, anti_analysis, discovery, crypto, network, execution. Max risk ~44 |
| `05_multithread.exe` | `src/multithread.c` `/O2` | Đa luồng thật + bộ ba injection (trơ) | `CreateThread`/`WaitForMultipleObjects`; **injection trio** `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread` trong IAT → capability `process_injection`, risk ~26 |
| `06_whoami.exe` | copy `System32\whoami.exe` | PE hệ thống **thật, lành tính** | ~375 function, 127 import; `AdjustTokenPrivileges`, discovery, network |
| `07_strings_sysinternals.exe` | `src/strings_fixture.c` `/O2` | String extractor + risk theo chuỗi | Chứa đủ pattern: `\\.\PhysicalDrive`, `cmd.exe`, `powershell`, `CurrentVersion\Run`, `http://`, `.onion` |

**`06`** dùng binary hệ thống thật vì đó là ví dụ import-phong-phú, hoàn toàn lành tính.
**`07`** *không* phải tiện ích `strings` của Sysinternals (không cài sẵn, và một công cụ
phân tích mã độc thì **không tải binary ngoài về**) — đây là fixture tổng hợp cùng vai trò,
nhồi các chuỗi giả (host `.invalid`/`.example`, IP TEST-NET `192.0.2.x`).

## Build lại

Cần Visual Studio với C++ workload (đã kiểm chứng: VS 2022 Community, MSVC 14.50).
Script tự tìm và gọi `vcvars64.bat`:

```bat
cd samples
build_samples.bat
```

Script biên dịch `src/*.c` → `NN_*.exe`, copy `whoami.exe`, và dọn file trung gian
(`.obj`/`.pdb`/`build\`). Không có compiler thì chỉ thiếu 01–05 và 07; `06` vẫn copy được.

> `.exe` bị `.gitignore` loại trừ (không commit binary) — build lại từ `src/` khi cần.
> Cảnh báo `vswhere.exe is not recognized` khi build là **vô hại**; đường dẫn vcvars
> đã hardcode nên toolchain vẫn nạp đúng.

## Dùng để test

Với backend + frontend đang chạy, upload từng file qua UI và kiểm:

- **01 vs 02** — cùng source, khác số function/block → minh hoạ ảnh hưởng của tối ưu lên CFG.
- **03** — double-click function lớn nhất, xem CFG có nhánh `TRUE`/`FALSE` và vòng lặp.
- **04** — mở **API Graph**, dùng bộ lọc *capability* để tách network / crypto / persistence...
- **05** — tìm `CreateRemoteThread`, xem risk score cao và capability `process_injection`.
- **07** — mở panel chi tiết / strings, xác nhận các chuỗi chỉ báo được trích xuất.

Lưu ý: risk **theo chuỗi** gán vào từng function phụ thuộc `data_references` của angr; trên
binary MSVC đã tối ưu, các chuỗi của `07` vẫn được **trích xuất đầy đủ** (hiện trong danh sách
strings) nhưng có thể không quy được về một function cụ thể — đúng như giới hạn đã nêu ở README chính.
