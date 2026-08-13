# Chuẩn bị VM + dbgsrv cho tính năng Debug

> Tài liệu này là hướng dẫn **chuẩn bị môi trường của người dùng** — VM, mạng, `dbgsrv`. App
> (`backend/app/dynamic/`) không thực hiện bất kỳ bước nào ở đây: nó chỉ kết nối tới `host:port`
> bạn nhập vào sau khi đã tự làm xong tất cả các bước dưới đây. Xem
> [`docs/dynamic-analysis-spec.md`](dynamic-analysis-spec.md) để biết đầy đủ ràng buộc an toàn.

> **Trạng thái hiện tại:** binding phía host là `ComtypesDebugBridge`
> (`backend/app/dynamic/debug_bridge/client.py`), không phải `pykd` — `pykd`'s bản mới nhất trên
> PyPI (`0.3.4.15`) chỉ có wheel tới Python 3.9, không cài được trên Python 3.14 mà dự án này dùng
> (đã xác nhận, `pip install pykd` báo lỗi ngay). `ComtypesDebugBridge` gọi thẳng `IDebugClient`/
> `IDebugControl`/`IDebugRegisters`/`IDebugSymbols` của `dbgeng.dll` qua `comtypes`/`ctypes`.
>
> **Chế độ "chạy trực tiếp" (mục 6) đã kiểm chứng thật** (2026-08-08), từ `DebugCreate` tới
> `WaitForEvent`/enumerate module/đọc instruction pointer — sau khi sửa 2 lỗi thật phát hiện qua
> chính lần test đó: (1) 5 vtable slot của `IDebugControl` bị sai do đếm nhầm — bỏ sót
> `STDMETHODV` (biến thể macro khác `STDMETHOD`, dễ bỏ sót khi đếm bằng mắt) khiến mọi slot sau đó
> lệch đi 3; (2) thiếu gọi `AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK | ...)` trước khi
> attach/create — không có nó, engine không bao giờ dừng lại ở bất kỳ event nào, tiến trình cứ chạy
> tự do (`WaitForEvent` chỉ trả về sau khi hết timeout, không có event thật nào được xử lý). Cả hai
> đã sửa và xác nhận lại bằng test trực tiếp (không qua app) trên chính máy này. Xem docstring của
> class `ComtypesDebugBridge` để biết chi tiết đầy đủ.
>
> **Vẫn chưa kiểm chứng**: breakpoint/step/đọc register trên một tiến trình local thật (chỉ mới xác
> nhận tới bước attach + đọc module đầu tiên), và toàn bộ luồng remote (`dbgsrv`) — dùng chung code
> vừa sửa nhưng chưa tự nó được test lại với một `dbgsrv` thật. Xem mục 9.

## 1. Tổng quan luồng

```
┌─────────────────────────────┐        TCP (host:port bạn nhập vào app)        ┌────────────────────────────┐
│ Máy host (chạy app này)     │ ───────────────────────────────────────────▶  │ VM cách ly (bạn tự chuẩn bị)│
│ - Debugging Tools for       │                                                 │ - dbgsrv.exe đang chạy      │
│   Windows (dbgeng.dll)      │                                                 │ - sample đã copy vào sẵn    │
│ - backend/app/dynamic/      │ ◀───────────────────────────────────────────  │ - network host-only, không  │
│   (ComtypesDebugBridge)     │        register/stack/breakpoint qua dbgeng    │   NAT ra Internet           │
└─────────────────────────────┘                                                 └────────────────────────────┘
```

App **không** cài đặt, khởi động, hay cấu hình bất cứ thứ gì ở cả hai phía — toàn bộ mục 2–6 dưới
đây là việc bạn tự làm trước khi bấm nút **Debug**.

## 2. Cài đặt trên máy host (máy chạy backend của app)

Cần `dbgeng.dll` (đi kèm Debugging Tools for Windows) có sẵn **trên chính máy host**, vì nó là thứ
tạo ra kết nối `IDebugClient` gọi ra `dbgsrv` từ xa — không phải VM cần nó cho việc này.

1. Cài **Debugging Tools for Windows**: cách dễ nhất là qua Windows SDK installer (chọn riêng mục
   "Debugging Tools for Windows"), hoặc qua `winget install Microsoft.WinDbg`.
2. Cài `comtypes` vào virtualenv backend (đã có trong `backend/requirements.txt`):
   ```bash
   backend\.venv\Scripts\python.exe -m pip install comtypes
   ```
3. Xác nhận `dbgeng.dll` load được và `DebugCreate` trả về một `IDebugClient` hợp lệ:
   ```bash
   backend\.venv\Scripts\python.exe -c "import ctypes; dbgeng = ctypes.WinDLL('dbgeng.dll'); print('OK', dbgeng)"
   ```
   Nếu bước này lỗi `OSError`, Debugging Tools for Windows chưa cài đúng chỗ trong `PATH`.

## 3. Chuẩn bị VM cách ly

Việc này hoàn toàn thủ công, theo cách bạn vẫn dùng cho phân tích mẫu thật (xem mục 10 của
[README.md](../README.md) — "vẫn nên phân tích mẫu thật trong máy ảo cách ly"):

1. Tạo/dùng lại một VM Windows cách ly (VirtualBox, VMware, Hyper-V — bất kỳ hypervisor nào, app
   không quan tâm và không điều khiển nó).
2. **Snapshot VM ở trạng thái sạch** trước khi làm bất cứ gì khác — để có thể revert lại sau khi
   debug xong. Đây là bước thủ công của bạn, app không tự động hoá.
3. **Cấu hình network cách ly**: đặt network adapter của VM ở chế độ **host-only** (không NAT/bridge
   ra Internet). Nếu muốn sample vẫn "tưởng" có mạng để quan sát hành vi, cân nhắc chạy một giả lập
   kiểu INetSim trên máy host và trỏ VM vào đó — việc này ngoài phạm vi app, tự cấu hình theo nhu
   cầu phân tích của bạn.
4. Cài **Debugging Tools for Windows** bên trong VM (cần `dbgsrv.exe`).
5. Copy sample cần debug vào VM — cách nào tùy bạn (shared folder, kéo thả, USB ảo...). App không
   tham gia bước này.

## 4. Chạy `dbgsrv` bên trong VM

Trong VM, mở `cmd`/PowerShell tại thư mục cài Debugging Tools for Windows và chạy:

```
dbgsrv.exe -t tcp:port=5005
```

(chọn cổng tuỳ ý, chỉ mở đúng cổng này qua adapter host-only — không mở ra rộng hơn mức cần thiết).

Có hai cách để `dbgsrv` thấy được sample, **cách chính xác cần bạn tự xác nhận lại khi thử thật**
(chỉ code phía host — vtable slot, GUID, struct layout — đã được đối chiếu với `DbgEng.h`; quy
trình vận hành `dbgsrv`/`cdb` phía VM thì chưa, vì không có VM nào để thử trong lúc viết tài liệu
này):

- **Cách A — chạy sample dưới quyền kiểm soát của debugger ngay từ đầu** (bắt được cả entry point):
  dùng `cdb.exe -server tcp:port=5005 -g "đường_dẫn_sample.exe"` thay cho `dbgsrv.exe` trần — cần
  đối chiếu cú pháp chính xác với tài liệu Microsoft.
- **Cách B — attach vào tiến trình đã chạy sẵn**: chạy sample thủ công trong VM trước (theo đúng
  quy trình cách ly bạn vẫn dùng), rồi kết nối `dbgsrv` và attach vào PID tiến trình đó từ phía app
  (trường `processId` khi kết nối) — sẽ bỏ lỡ code chạy trước thời điểm attach.
  `ComtypesDebugBridge.attach()` hiện **chỉ hỗ trợ Cách B** (attach theo `processId`) - attach theo
  `processName` cần thêm một lời gọi `IDebugSymbols::GetModuleByModuleName` hoặc tương đương, chưa
  cài đặt.

## 5. Kết nối từ app (chế độ remote)

1. Chạy static analysis cho sample như bình thường trước (nút Debug chỉ bật sau khi đã có kết quả
   phân tích tĩnh).
2. Bấm **Debug** trên toolbar → đọc và xác nhận modal cảnh báo bắt buộc (nêu rõ đây là thực thi
   thật, và việc cách ly/network/snapshot VM là trách nhiệm của bạn, app không kiểm soát được) →
   chọn **"Remote (VM/máy khác)"** ở bước chọn chế độ.
3. Nhập `host:port` của `dbgsrv` đang chạy trong VM (ví dụ `192.168.56.10:5005` nếu dùng adapter
   host-only riêng, hoặc `127.0.0.1:5005` nếu bạn tự thiết lập port-forward tới VM theo cách khác)
   — cùng `processId` nếu dùng Cách B ở mục 4.
4. App kết nối, attach, và hiển thị panel debug (register/stack/breakpoint) cạnh graph tĩnh đã có
   — địa chỉ runtime được tự động dịch sang địa chỉ tĩnh để tô sáng đúng node.

Nếu kết nối thất bại hoặc `host:port` chưa nhập, app chỉ báo lỗi rõ ràng — không có phương án dự
phòng nào khác được thử (không tự chạy sample ở bất kỳ đâu).

## 6. Chạy trực tiếp trên máy này (không qua VM/dbgsrv)

> **⚠️ Chế độ này khiến app trực tiếp thực thi file bạn chỉ định, ngay trên máy đang chạy app —
> không qua VM, không cách ly nào cả.** Đây là ngoại lệ tường minh với nguyên tắc "sample không bao
> giờ được thực thi" (README.md mục 10), thêm vào theo yêu cầu rõ ràng của người dùng dự án — xem
> phần bổ sung "local-launch" trong `docs/dynamic-analysis-spec.md`. **Chỉ dùng cho phần mềm bạn
> hoàn toàn tin cậy** (vd. chính app Binary Graph Analyzer đang phát triển). **Không dùng cho mẫu
> chưa xác định/nghi ngờ** — dùng chế độ remote + VM cách ly (mục 4–5) cho trường hợp đó.

Không cần cài `dbgsrv.exe`/chuẩn bị VM gì cả — chỉ cần `dbgeng.dll` trên máy host (mục 2) và
`comtypes` đã cài trong virtualenv backend.

### Cách A — chạy đúng file vừa upload (một cú click, mặc định)

Trình duyệt vẫn giữ nguyên file gốc bạn chọn lúc upload trong bộ nhớ (bản trên đĩa của static
analyzer thì đã bị xóa ngay sau khi phân tích xong) — app gửi lại đúng bytes đó sang một endpoint
riêng của `app/dynamic/`, tự lưu ra một bản sao **mới, tách biệt** (thư mục riêng
`.../binary-graph-analyzer/dynamic-local-launch/`, không liên quan gì tới thư mục upload của static
analyzer), rồi chạy bản sao đó.

1. Chạy static analysis như bình thường (giữ nguyên tab/trang — file gốc chỉ còn trong bộ nhớ
   trình duyệt của phiên hiện tại, đóng tab là mất).
2. Bấm **Debug** → xác nhận modal cảnh báo chung → ở bước chọn chế độ, bấm **"Chạy trực tiếp trên
   máy này"**.
3. Đọc và xác nhận modal cảnh báo **riêng, nghiêm trọng hơn**, hiện lại **mỗi lần** chọn chế độ này
   — tick ô xác nhận "file này an toàn".
4. Bấm nút **"Chạy file vừa upload: `<tên file>` (`<kích thước>`)"** — app tự upload lại, lưu bản
   sao riêng, và chạy ngay.

### Cách B — chạy một file khác bằng đường dẫn thủ công

Vẫn có sẵn ở cùng bước 3 phía trên, bên dưới nút "Chạy file vừa upload": nhập đường dẫn đầy đủ (và
tham số nếu có) tới một file khác, ví dụ:
```
C:\path\to\app.exe --some-flag
```
rồi bấm **Chạy**. Dùng khi muốn debug một file không phải file vừa upload (vd. đã upload sample A để
phân tích tĩnh nhưng muốn debug trực tiếp file B).

Cả hai cách đều thực thi file trực tiếp qua `IDebugClient::CreateProcessAndAttach` của `dbgeng.dll`
(không phải qua `subprocess`/shell) và attach ngay từ entry point.

Kỹ thuật: `ComtypesDebugBridge.create_and_attach_local()` tự làm `DebugCreate` + gọi thẳng
`CreateProcessAndAttach` với `Server=0` (nghĩa là máy cục bộ) — không cần `ConnectProcessServer`
hay `dbgsrv` nào. Slot vtable/flag dùng ở đây (`CreateProcessAndAttach` slot 14,
`DEBUG_ONLY_THIS_PROCESS`) đã đối chiếu với `DbgEng.h` thật giống các thao tác khác trong file này
— nhưng **bản thân việc chạy thật một tiến trình qua đường này chưa được thử nghiệm trong môi
trường viết code** (không có gì an toàn để chạy thử ở đó). Thử với một file lành tính trước khi tin
tưởng hoàn toàn.

Bản sao được stage (Cách A) chỉ tồn tại trong suốt phiên debug — xóa best-effort khi phiên đóng
(Disconnect, idle timeout 30 phút, hoặc bị evict do vượt số phiên tối đa), qua đúng cơ chế dọn dẹp
`DebugSession.disconnect()` đã dùng cho các phiên khác. Không đảm bảo xóa ngay lập tức nếu OS vẫn
giữ file ảnh đang chạy — chỉ là best-effort, không phải hành vi bảo đảm.

## 7. Sau khi debug xong

- Đóng phiên debug trong app (nút Disconnect, hoặc phiên tự ngắt sau 30 phút không hoạt động).
- **Tự revert VM về snapshot sạch** (mục 3, bước 2) trước khi dùng lại VM cho mẫu khác — app không
  tự động việc này. (Không áp dụng cho chế độ chạy trực tiếp — không có VM nào để revert.)

## 8. Giới hạn hiện tại (giai đoạn 1)

- Chỉ đọc: breakpoint, step, đọc register/stack. **Chưa hỗ trợ ghi/patch register hay memory**
  (giai đoạn 2, xem `docs/dynamic-analysis-spec.md`).
- Bộ register đọc được hiện là tập x86 cơ bản (`eax`..`eip`) — cần mở rộng sang x64 khi thử với
  sample 64-bit thật.
- Attach chỉ hỗ trợ theo `processId`, chưa hỗ trợ `processName` (mục 4).
- `ModuleInfo.moduleName`/`.size` không lấy được từ dbgeng thật (`IDebugSymbols::GetModuleNames`
  chưa cài đặt) — tên module hiện chỉ là tên tiến trình người dùng đã biết, size luôn là 0. Không
  ảnh hưởng tới đồng bộ địa chỉ (chỉ dùng `load_base`, lấy đúng từ `GetModuleByIndex`).
- **Chưa kiểm chứng với một `dbgsrv` thật, và chế độ chạy trực tiếp (mục 6) chưa kiểm chứng với
  một tiến trình thật** — xem mục 9.

## 9. Việc còn lại: kiểm chứng với một `dbgsrv`/tiến trình thật

Không giống bản `PykdDebugBridge` trước đó (không cài được `pykd` nên không chạy được gì cả),
`ComtypesDebugBridge` hiện đã có đầy đủ: `DebugCreate` load `dbgeng.dll` thật, toàn bộ vtable slot/
GUID/struct layout đối chiếu byte-for-byte với `DbgEng.h` (Windows SDK 10.0.26100.0, xem chi tiết
trong docstring của class `ComtypesDebugBridge`), và 4 GUID (`IDebugClient`/`IDebugControl`/
`IDebugRegisters`/`IDebugSymbols`) đã xác nhận thêm bằng một lệnh gọi `DebugCreate`+`QueryInterface`
thật, trả về `S_OK` cho cả bốn.

Cái duy nhất chưa kiểm chứng được là **hành vi thật khi nói chuyện với một `dbgsrv` đang chạy** -
không có VM/dbgsrv nào trong môi trường viết code này để thử. Khi bạn đã hoàn tất mục 2–4:

1. Chạy static analysis cho một sample lành tính đã biết rõ control flow (ví dụ
   `samples/01_simple_debug.exe`).
2. Làm theo mục 5 để kết nối debug session thật.
3. Nếu `connect`/`attach` thất bại: đọc thông báo lỗi (kèm HRESULT hex) - so khớp với tài liệu
   `IDebugClient::ConnectProcessServer`/`AttachProcess` của Microsoft để biết chính xác bước nào sai
   (thường là do dbgsrv chưa đúng trạng thái attach - xem lại Cách A/B ở mục 4).
4. Nếu `connect`/`attach` thành công nhưng breakpoint/step/register cho kết quả sai: đối chiếu lại
   `_SLOT_*`/struct layout trong `client.py` với `DbgEng.h` trên chính máy bạn (đường dẫn có thể
   khác `10.0.26100.0` tuỳ bản SDK đã cài) - dù đã đối chiếu cẩn thận, đây vẫn là bước xác nhận cuối
   cùng trước khi tin tưởng hoàn toàn, đúng tinh thần MVP acceptance criterion đã nêu trong
   `docs/dynamic-analysis-spec.md`.
5. Xác nhận tô sáng đúng node trên graph tĩnh khi dừng ở một địa chỉ đã biết trước (so khớp thủ
   công) - đây là tiêu chí chấp nhận chính của giai đoạn 1.

Cập nhật lại tài liệu này (và xoá các ghi chú "chưa kiểm chứng") sau khi hoàn tất.
