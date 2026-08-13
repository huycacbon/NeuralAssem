# Prompt: Module Dynamic Analysis (sandbox VM cách ly) cho Binary Graph Analyzer

> Dán prompt này vào một session/luồng làm việc **riêng** (không phải session đang phát triển
> static analyzer) khi bắt đầu implement. Mục đích tách biệt: dynamic analysis là một product
> line có risk model khác hẳn static analyzer hiện tại, không nên trộn lẫn quá trình phát triển.

## Bối cảnh

`C:\MalwareAnalysis` là "Binary Graph Analyzer" — công cụ phân tích **tĩnh** file PE bằng angr,
chạy hoàn toàn local, hiển thị kết quả dưới dạng graph tương tác (Cytoscape.js). Xem
[`README.md`](../README.md) để hiểu kiến trúc đầy đủ, đặc biệt mục 10 "Lưu ý an toàn" và test
`test_sample_is_never_executed` trong `backend/tests/` — invariant cốt lõi hiện tại là **sample
không bao giờ được thực thi**, thực thi bằng `subprocess`/`os.system`/`os.spawn` bị cấm hoàn toàn
trong `backend/app/`.

Yêu cầu bây giờ: thêm một **debugger thật** (breakpoint, step, xem register/memory sống — không
phải chỉ log hành vi rồi hiển thị lại) — bổ sung cho static analyzer chứ không thay thế.

## Luồng UI mong muốn (nguyên văn yêu cầu người dùng)

1. Có nút **"Debug"** trên toolbar, cạnh các nút graph/export hiện có.
2. Bấm vào: nếu risk score/heuristic của sample (đã tính sẵn từ static analysis,
   `app/analyzers/risk_scorer.py`) cho thấy khả năng cao là mã độc thật, hiện **modal cảnh báo bắt
   buộc dừng lại** — không phải toast/log — nói rõ: đây là debug thật, phải chuyển sang máy ảo cách
   ly, không debug trực tiếp trên máy đang chạy app. Người dùng phải xác nhận đã hiểu mới được tiếp
   tục.
3. Sau khi xác nhận: người dùng nhập `host:port` của `dbgsrv` (đã tự chạy sẵn trong VM họ tự chuẩn
   bị, sample cũng đã tự đưa vào từ trước) — app kết nối tới, mở phiên debug thật (breakpoint, step
   qua từng instruction, xem register/stack) — điều khiển từ UI trên host, thực thi trong VM. App
   không tự khởi động VM hay copy file vào, chỉ kết nối tới thứ người dùng đã chuẩn bị sẵn.
4. **Đồng bộ địa chỉ:** VM load binary ở địa chỉ runtime thật (có thể lệch so với `ImageBase` tĩnh
   do ASLR/rebase). Khi debugger đang dừng ở một địa chỉ runtime, phải tính lại
   `static_address = runtime_address - (actual_load_base - preferred_image_base)` để tô sáng đúng
   node/basic block tương ứng trên graph tĩnh đã hiển thị sẵn — người dùng thấy "đang chạy ở đâu"
   ngay trên cùng graph đã dùng để phân tích tĩnh, không phải nhìn hai giao diện tách rời.

## Kiến trúc debug bridge đề xuất — dùng WinDbg/`dbgeng`, không tự viết debug protocol

Windows đã có sẵn cơ chế remote debugging đúng chính xác use case này (debug trên máy khác, điều
khiển từ máy phân tích): **Debugging Tools for Windows** (đi kèm WinDbg, miễn phí từ Microsoft).

- Bên trong VM: chạy `dbgsrv.exe -t tcp:port=<port>` rồi attach nó vào tiến trình sample (hoặc chạy
  sample dưới quyền kiểm soát của `dbgsrv` ngay từ đầu để bắt được cả entry point).
- Trên host: app kết nối tới `dbgsrv` qua TCP bằng `dbgeng.dll` (qua Python binding như `pykd`,
  hoặc gọi trực tiếp qua `comtypes`/`ctypes` vào `IDebugClient`) để set breakpoint, step, đọc
  register/memory — **không tự viết debug engine từ đầu**, tận dụng engine đã được Microsoft kiểm
  chứng nhiều năm.
- `dbgeng` tự báo địa chỉ load thật của module qua `IDebugSymbols::GetModuleByModuleName` /
  lệnh `lm` — dùng trực tiếp để tính delta rebase ở mục 4 phía trên, không cần tự dò ASLR.
- Kênh TCP giữa host và VM: khuyến nghị người dùng tự cấu hình VM dùng network adapter host-only
  (không NAT ra Internet) khi tự chuẩn bị VM — app chỉ kết nối tới `host:port` được nhập vào, không
  tự kiểm soát hay xác thực được cấu hình network của VM đó (xem mục an toàn #4).

## Ràng buộc an toàn — KHÔNG được vi phạm, không thương lượng

1. **App không tự động hoá VM và không đụng tới sample để chuyển vào VM.** Người dùng tự chuẩn bị
   VM, tự copy sample vào bên trong (kéo thả, shared folder, USB ảo — cách nào tuỳ người dùng, app
   không quan tâm), và tự chạy `dbgsrv.exe` bên trong VM đó. App **chỉ là một debug client**: nhận
   `host:port` của `dbgsrv` đang chạy sẵn rồi kết nối tới qua TCP — không có `vm_driver/`, không
   subprocess gọi hypervisor CLI, không tự start/stop/snapshot VM. Đây thực ra là ràng buộc an toàn
   *mạnh hơn* bản trước: app hoàn toàn không có code nào điều khiển VM hay chạm vào sample file cả,
   chỉ mở một kết nối mạng tới điểm cuối debug do người dùng tự đưa vào.
2. **Tách code hoàn toàn khỏi static analyzer hiện có.** Module mới nằm ở package riêng (đề xuất
   `backend/app/dynamic/`), không sửa `backend/app/analyzers/`, `services/analysis_service.py`,
   `services/file_service.py`, hay bất cứ gì trong phạm vi test
   `test_sample_is_never_executed` đang quét. Import một chiều: `dynamic/` có thể đọc kết quả từ
   static analyzer để hiển thị chung, nhưng static analyzer không được biết gì về `dynamic/`.
3. **Test riêng cho module mới, đối xứng với test tĩnh hiện có:** khẳng định code trong
   `backend/app/dynamic/` không bao giờ gọi `subprocess`/`exec`/`os.system` nhắm vào sample file
   hay vào bất kỳ hypervisor nào — toàn bộ tương tác với "thế giới bên ngoài" chỉ là socket TCP tới
   `dbgsrv` (một địa chỉ do người dùng nhập, không phải đường dẫn file).
4. **Network của VM là trách nhiệm người dùng tự cấu hình** khi chuẩn bị VM (khuyến nghị: chặn
   hoặc giả lập kiểu INetSim, chỉ mở đúng port `dbgsrv` qua adapter host-only). App không có cách
   nào tự kiểm soát network của VM vì không tự động hoá VM — modal cảnh báo (mục 6) phải nhắc rõ
   đây là trách nhiệm người dùng, không phải app tự đảm bảo.
5. **Snapshot/revert VM (nếu người dùng có dùng) là quy trình thủ công của người dùng**, không phải
   thứ app tự động hoá — vì app không có quyền điều khiển VM. Có thể ghi vào modal cảnh báo (mục 6)
   như một gợi ý nhắc người dùng tự revert trước/sau khi debug, nhưng không phải bước app tự thực
   hiện.
6. **Cảnh báo tường minh trong UI**, không chỉ log: lần đầu bấm nút **"Debug"** phải có modal xác
   nhận riêng (không phải toast/checkbox ẩn) — nêu rõ sample sẽ được **thực thi thật** trong VM mà
   người dùng đã tự chuẩn bị, và việc cách ly/network/snapshot của VM đó là trách nhiệm của người
   dùng, app không kiểm soát được. Yêu cầu xác nhận đã hiểu trước khi cho nhập `host:port` của
   `dbgsrv` và mở phiên debug.
7. **Không tự động chạy kèm static analysis.** Đây luôn là hành động người dùng chủ động chọn cho
   một sample cụ thể, không bao giờ trigger ngầm.
8. Nếu người dùng chưa cung cấp `host:port` của một `dbgsrv` đang chạy, hoặc kết nối thất bại — báo
   lỗi rõ ràng, không có fallback nào khác (không tự thử chạy sample ở đâu cả).

## Kiến trúc thư mục đề xuất

Không có `vm_driver/` — app không điều khiển VM. Chỉ có debug client:

```
backend/app/dynamic/
├── debug_bridge/           Kết nối tới dbgsrv đã chạy sẵn trong VM (xem mục kiến trúc debug bridge
│                           ở trên) - người dùng tự khởi động dbgsrv, tự đưa sample vào VM
│   ├── client.py           Wrap dbgeng qua pykd/comtypes: connect(host, port), attach, breakpoint,
│   │                       step, đọc register/memory, lấy module base address thật
│   └── address_map.py      Tính delta rebase (runtime_base - preferred ImageBase) và chuyển đổi
│                           2 chiều runtime_address <-> static_address đã dùng trong
│                           app.models.graph.Graph hiện có
├── session.py              State machine 1 phiên debug: xác nhận modal cảnh báo đã đọc -> nhận
│                           host:port từ người dùng -> connect debug_bridge -> (người dùng tương
│                           tác: step/breakpoint/patch) -> disconnect khi đóng phiên
└── config.py                dbgsrv host/port mặc định (nếu người dùng muốn lưu lại), timeout kết
                            nối - không có gì liên quan tới VM lifecycle
```

Điểm tích hợp UI: nút **"Debug"** trên `GraphToolbar` (cạnh `onExport` hiện có,
xem `frontend/src/components/GraphToolbar.tsx`), disabled tới khi đã có static analysis. Bấm vào
→ modal cảnh báo (component mới, kiểu `ConfirmDialog`) → nếu xác nhận, mở một panel debug mới
(register/stack/breakpoint list) cạnh disassembly panel đã có trong `NodeDetails.tsx` — graph hiện
tại tô sáng node tương ứng địa chỉ runtime hiện tại qua `address_map.py`, tái dùng đúng cơ chế
highlight-node đã có sẵn cho việc chọn node.

## Phạm vi giai đoạn 1 (MVP) — đề xuất, không phải bắt buộc

Debugger thật nhưng **chỉ đọc** trước — chứng minh luồng an toàn + đồng bộ địa chỉ hoạt động đúng
trước khi cho phép sửa state của tiến trình đang chạy:

- Kết nối `debug_bridge` tới một `dbgsrv` đã chạy sẵn (người dùng tự chuẩn bị VM + sample + dbgsrv,
  chỉ nhập `host:port` vào app).
- Attach vào sample đã chạy trong VM, set breakpoint, step qua instruction, đọc register/stack —
  nhưng CHƯA cho ghi/patch register hay memory.
- Graph tĩnh tô sáng đúng node đang chạy theo địa chỉ runtime (kiểm chứng bằng một sample benign đã
  biết rõ control flow trước, so khớp thủ công).
- CHƯA cần: ghi/patch register hoặc memory rồi chạy tiếp (để giai đoạn 2, sau khi giai đoạn đọc đã
  ổn định và đồng bộ địa chỉ đã kiểm chứng đúng qua vài sample benign).

## Giai đoạn 2 — sửa code/register rồi tiếp tục chạy (patch-and-continue)

Chỉ bắt đầu sau khi giai đoạn 1 (đọc + đồng bộ địa chỉ) đã chạy ổn định. Mở rộng `debug_bridge/client.py`:

- `write_register(name, value)` — qua `IDebugRegisters::SetValue`.
- `write_memory(address, bytes)` — qua `IDebugDataSpaces::WriteVirtual`. Đây là chỗ patch
  instruction (vd. NOP một lệnh `jz` để né anti-debug check) hoặc sửa giá trị biến.
- `continue_execution()` / `step_over()` / `step_into()` — qua
  `IDebugControl::SetExecutionStatus`.

UI thêm vào debug panel (từ giai đoạn 1):
- Sửa giá trị register ngay tại chỗ khi debugger đang dừng ở breakpoint.
- "Patch bytes" ngay trên dòng instruction đang chọn trong panel disassembly đã có sẵn — dùng lại
  `address_map.py` nếu người dùng chọn patch từ view tĩnh trước khi vào phiên debug.
- Nút Continue/Step để chạy tiếp sau khi patch.

**An toàn bổ sung riêng cho giai đoạn 2** (khác giai đoạn 1 ở chỗ giờ chủ động đổi hành vi thực thi,
không chỉ quan sát):

1. **Log mọi patch** (address, byte cũ, byte mới, timestamp) thành audit trail riêng cho phiên —
   xem lại được "đã sửa gì" sau này.
2. **Undo trong phiên:** giữ byte gốc để revert riêng một patch mà không cần revert cả VM, nếu
   người dùng muốn thử patch khác.
3. **Cảnh báo riêng cho patch đầu tiên trong một phiên** (tách khỏi cảnh báo mở phiên debug ở mục
   an toàn #6): patch thường dùng để bypass anti-debug/anti-VM check — một khi bypass thành công,
   malware có thể bắt đầu hành vi mà trước đó nó cố tình không làm khi phát hiện đang bị theo dõi
   (vd. network traffic, lan truyền). Modal phải nhắc lại: xác nhận VM vẫn đang theo đúng chính sách
   network đã cấu hình (mục an toàn #4) TRƯỚC khi cho phép patch đầu tiên có hiệu lực.
4. Patch chỉ tồn tại trong bộ nhớ tiến trình đang debug (qua `WriteVirtual`), app không ghi gì
   xuống ổ đĩa VM. Việc dọn VM về trạng thái sạch sau khi patch (revert snapshot, nếu người dùng có
   dùng) vẫn là việc người dùng tự làm (mục an toàn #5) — modal đóng phiên nên nhắc lại điều này
   một lần nữa, không ngầm định là "đã dọn sạch".

## Ngoài phạm vi (không làm trong giai đoạn này)

- **App tự động hoá VM (start/stop/snapshot/copy file) — không làm, kể cả sau này.** Đây là ranh
  giới cố định của thiết kế: người dùng tự quản lý VM, app chỉ là debug client. Nếu sau này muốn
  tiện hơn (app tự start VM chẳng hạn), đó là một quyết định mới cần bàn riêng, không phải mặc định
  mở rộng dần từ spec này.
- Không cho phép network thật ra Internet mặc định (khuyến nghị cho người dùng khi họ tự cấu hình
  VM, xem mục an toàn #4).
- Giai đoạn 1 chưa cho ghi/patch register/memory (xem MVP ở trên) — chỉ đọc + step.

## Câu hỏi PHẢI hỏi người dùng trước khi viết code

1. VM đã có sẵn `dbgsrv.exe` (từ Debugging Tools for Windows) và sample đã được copy vào chưa, hay
   cần hướng dẫn cài/chuẩn bị từ đầu?
2. Muốn dùng `pykd` (binding Python có sẵn cho `dbgeng`, ít code hơn) hay tự bind qua
   `comtypes`/`ctypes` trực tiếp vào `IDebugClient`?
3. `dbgsrv` sẽ nghe trên `host:port` cố định hay nhập tay mỗi lần debug?
4. Timeout mong muốn cho một phiên debug (tự động ngắt kết nối nếu người dùng bỏ đi giữa chừng)?

Không cần hỏi về hypervisor cụ thể hay snapshot — đó là việc của người dùng, ngoài phạm vi code của
app.

---

## Bổ sung: chế độ "local-launch" (app tự thực thi trực tiếp trên host)

**Trạng thái: đã triển khai**, sau khi toàn bộ phần trên (chế độ remote, MVP giai đoạn 1) đã xong.
Người dùng dự án yêu cầu thêm khả năng debug **trực tiếp trên máy đang chạy app**, với app tự thực
thi file mục tiêu — không qua VM, không qua `dbgsrv` thủ công.

**Đây là thay đổi trực tiếp tới ràng buộc an toàn #1 ở trên**, vốn ghi "không thương lượng". Trước
khi triển khai, người dùng đã được hỏi rõ và xác nhận **hai lần** (không phải một), sau khi được
giải thích cụ thể hậu quả: *"Có, tôi hiểu rõ rủi ro và vẫn muốn app tự chạy file .exe"* — tức là
xác nhận rằng nguyên tắc "sample không bao giờ được thực thi" (README.md mục 10,
`test_sample_is_never_executed`) **không còn đúng cho toàn bộ tool nữa** một khi tính năng này tồn
tại, vì code không có cách nào phân biệt "file tin cậy của người dùng" với "một sample malware
thật" — cả hai chỉ là một chuỗi đường dẫn.

### Phạm vi đã triển khai

- Một phương thức mới, **duy nhất**:
  `app.dynamic.debug_bridge.client.ComtypesDebugBridge.create_and_attach_local(command_line)` — gọi
  thẳng `IDebugClient::CreateProcessAndAttach` của `dbgeng.dll` với `Server=0` (máy cục bộ), không
  qua `dbgsrv`/`ConnectProcessServer`. Vtable slot (14) và cờ `DEBUG_ONLY_THIS_PROCESS` đối chiếu
  với `DbgEng.h` thật giống mọi thao tác khác trong file này (xem docstring của class).
- Endpoint mới `POST /dynamic/sessions/local` (và `debug_launch_local` phía desktop bridge) — tách
  biệt hoàn toàn khỏi endpoint remote (`POST /dynamic/sessions`), không dùng chung model request,
  để hai luồng code (chỉ quan sát vs. tự thực thi) không lẫn vào nhau.
- `DebugSession.launch_local()` ghi log cảnh báo (audit trail) mọi lệnh được chạy — `command_line`,
  `session_id`, `analysis_id` — thao tác duy nhất trong cả package có audit log riêng.
- Test riêng `test_local_launch_is_isolated_to_one_method`
  (`backend/tests/test_dynamic_security.py`) khẳng định khả năng tạo tiến trình chỉ tồn tại đúng
  trong `ComtypesDebugBridge.create_and_attach_local`, không rò rỉ ra chỗ khác trong `app/dynamic/`.
- Frontend: modal Debug có thêm bước chọn chế độ (remote/local), và chế độ local có cảnh báo **riêng
  biệt, hiện lại mỗi lần** (không phải một lần mỗi phiên trang như cảnh báo chung) kèm checkbox xác
  nhận bắt buộc trước khi nhập command line.

### Những gì KHÔNG đổi

- Chế độ remote (toàn bộ nội dung phía trên tài liệu này) không thay đổi — vẫn là debug client thuần
  tuý, không tự động hoá VM, không thực thi gì.
- Static analyzer (`app/analyzers/`, `app/services/`) hoàn toàn không bị ảnh hưởng — nguyên tắc
  "không thực thi binary" vẫn đúng tuyệt đối cho toàn bộ luồng phân tích tĩnh.
- `test_sample_is_never_executed` không sửa code, chỉ thêm ghi chú docstring làm rõ phạm vi thật của
  nó (nó chỉ bắt được API cấp Python như `subprocess`, không bắt được lời gọi COM
  `CreateProcessAndAttach`).

Xem `docs/dynamic-analysis-vm-setup.md` mục 6 để biết cách dùng, và
`backend/app/dynamic/debug_bridge/client.py`'s `create_and_attach_local` docstring để biết chi tiết
kỹ thuật đầy đủ.

### Bổ sung tiếp theo: chạy trực tiếp đúng file vừa upload (một click, không gõ đường dẫn)

**Trạng thái: đã triển khai.** Sau khi phần "local-launch" ở trên xong (vẫn phải tự gõ đường dẫn),
người dùng yêu cầu bỏ luôn bước gõ tay: upload sample xong, một nút là debug đúng file đó.

Vì file gốc bị xóa ngay sau khi phân tích tĩnh (`file_service.py`, file bị cấm sửa), không thể "chạy
lại đúng file cũ". Cơ chế thay thế — được người dùng xác nhận **ba lần**, lần cuối với mô tả kỹ
thuật cụ thể — là: `app/dynamic/` có một pipeline upload+lưu+chạy **hoàn toàn độc lập** (endpoint
riêng, thư mục temp riêng, dùng lại `app/utils/security.py` — utility không nằm trong danh sách cấm
— để validate giống hệt luồng upload tĩnh). Frontend gửi lại đúng bytes file đã chọn (vẫn còn trong
bộ nhớ trình duyệt) sang endpoint này. Không đụng `file_service.py`/`services/analysis_service.py`,
không phá quy tắc import một chiều — nhưng hệ quả thực tế: **upload → Debug → xác nhận là đủ để app
thực thi bất kỳ file nào được upload, không còn bước thủ công nào cả.** Người dùng xác nhận hiểu rõ
điều này trước khi triển khai.

Xem `backend/app/dynamic/local_upload.py` và mục 6 (Cách A) của `docs/dynamic-analysis-vm-setup.md`
để biết chi tiết.
