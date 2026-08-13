# Backend — Binary Graph Analyzer

FastAPI + angr. Phân tích **tĩnh** file PE và trả về graph đã chuẩn hóa.

> Backend không bao giờ thực thi file mẫu. Xem phần "An toàn" bên dưới.

## Cài đặt

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Yêu cầu Python 3.11+ (đã kiểm chứng trên CPython 3.14.4 x64).

> **Không** dùng `pip install --only-binary=:all:` — dependency `mulpyplexer` chỉ có sdist
> thuần Python và lệnh sẽ thất bại với `ResolutionImpossible`.

## Chạy

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- API docs: <http://127.0.0.1:8000/docs>
- Health: <http://127.0.0.1:8000/api/health>

## Test

```bash
pytest tests -v
```

Integration test cần một file PE. Thứ tự tìm kiếm:

1. Biến môi trường `BGA_TEST_PE`
2. `tests/fixtures/sample.exe` (compile từ `tests/fixtures/sample.c`)
3. Một binary hệ thống Windows lành tính, chỉ đọc

Trên nền tảng không có PE nào, test tự skip.

## Kiến trúc module

| Module | Trách nhiệm |
|---|---|
| `api/` | Định tuyến HTTP, chuyển exception thành error envelope |
| `services/file_service.py` | Validate upload, ghi file tạm UUID, đảm bảo xóa trong `finally` |
| `services/analysis_service.py` | Điều phối một lần phân tích, phục vụ truy vấn tiếp theo |
| `analyzers/angr_analyzer.py` | Driver angr; trích xuất mọi thứ ra dataclass thuần Python |
| `analyzers/call_graph_builder.py` | Call graph + API graph, giới hạn depth và số node |
| `analyzers/cfg_builder.py` | CFG của một function |
| `analyzers/import_extractor.py` | Import table (pefile, fallback CLE) |
| `analyzers/string_extractor.py` | Strings toàn file và theo từng function |
| `analyzers/risk_scorer.py` | Heuristic triage (API + string) |
| `repositories/` | Interface lưu trữ + bản in-memory |
| `models/` | Pydantic models (JSON camelCase, Python snake_case) |
| `utils/` | Chuẩn hóa địa chỉ, validate upload, hash |

### Vì sao trích xuất toàn bộ ngay lập tức

`angr.Project` giữ file được map để disassembly lazy. Nhưng yêu cầu là **xóa file mẫu ngay khi
phân tích xong**. Vì vậy `angr_analyzer` trích xuất mọi thứ cần thiết (function, block,
instruction, call edge, string) ra dataclass **trong lúc project còn sống**, rồi thả project.
Các request sau (`/functions/{addr}/cfg`) được phục vụ từ dataclass đó — HTTP layer vẫn trả
lazy nên response đầu tiên vẫn nhỏ.

## Cấu hình

Biến môi trường tiền tố `BGA_` (hoặc file `.env`):

| Biến | Mặc định |
|---|---|
| `BGA_HOST` | `127.0.0.1` |
| `BGA_PORT` | `8000` |
| `BGA_ENVIRONMENT` | `development` |
| `BGA_MAX_UPLOAD_MB` | `100` |
| `BGA_ANALYSIS_TIMEOUT_SECONDS` | `300` |
| `BGA_MAX_STORED_ANALYSES` | `16` |
| `BGA_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,...` |

Đặt `BGA_ENVIRONMENT=production` để lược bỏ `details` khỏi error response.

## An toàn

- Không `subprocess` / `os.system` / `os.spawn` / Wine / emulator — có test chặn hồi quy.
- `angr.Project(..., auto_load_libs=False)`, chỉ disassembly, không step state.
- Tên file upload không bao giờ dùng làm đường dẫn; file tạm là `<tempdir>/<uuid><ext>`.
- Giới hạn dung lượng ngay khi stream; file dở dang bị xóa trước khi lỗi lan ra.
- File tạm xóa trong `finally` trên mọi nhánh.
- Bind loopback, CORS chỉ frontend local.
- Log không chứa nội dung binary.

## Ghi chú vận hành

- angr in cảnh báo `failed loading "unicornlib.dll", unicorn support disabled` khi khởi động.
  Vô hại — unicorn chỉ dùng cho emulation, mà công cụ này không emulate.
- Log của `angr`, `cle`, `pyvex`, `claripy` bị hạ xuống `ERROR` trong `main.py` vì rất ồn ở `INFO`.
