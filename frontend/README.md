# Frontend — Binary Graph Analyzer

React + TypeScript + Vite + Cytoscape.js. Không dùng framework backend Node.js —
Vite chỉ phục vụ static asset và dev server.

## Cài đặt

```bash
npm install
copy .env.example .env
```

## Chạy

```bash
npm run dev
```

<http://127.0.0.1:5173>. Backend phải chạy sẵn tại <http://127.0.0.1:8000>.

## Build

```bash
npm run build
npm run preview
```

## Cấu hình

`.env`:

```text
VITE_API_BASE_URL=http://127.0.0.1:8000
```

## Cấu trúc

| Đường dẫn | Trách nhiệm |
|---|---|
| `src/App.tsx` | Vòng đời phân tích, graph nào đang hiển thị, node nào đang chọn |
| `src/components/GraphToolbar.tsx` | Upload, chọn graph type, layout, search, fit/reset/labels |
| `src/components/GraphViewer.tsx` | Canvas Cytoscape, tương tác, highlight |
| `src/components/graphStyle.ts` | Stylesheet + layout preset của Cytoscape |
| `src/components/FunctionList.tsx` | Panel trái: danh sách function |
| `src/components/NodeDetails.tsx` | Panel phải: chi tiết function / block / API |
| `src/components/AnalysisSummary.tsx` | Tổng quan file + bộ lọc |
| `src/components/GraphLegend.tsx` | Chú giải + trạng thái |
| `src/components/BinaryUpload.tsx` | File picker + progress |
| `src/hooks/useGraphFilters.ts` | State bộ lọc + predicate thuần |
| `src/services/analysisApi.ts` | REST client, `ApiError` có `code`/`details` |
| `src/types/graph.ts` | Wire types khớp Pydantic models |
| `src/styles/` | CSS variables cho light/dark |

## Nguyên tắc thiết kế

**Bộ lọc không phá dữ liệu.** Toàn bộ graph luôn nằm trong Cytoscape; lọc chỉ bật/tắt class
`.filtered-out`. Nhờ đó bỏ lọc là tức thời và dữ liệu gốc không bao giờ mất.

**Không phụ thuộc màu sắc đơn thuần.** Node kind được mã hóa bằng **cả hình dạng lẫn màu**:

| Loại | Hình dạng |
|---|---|
| Function | Tròn |
| API | Chữ nhật bo góc |
| Basic block | Chữ nhật |
| String | Thoi |
| Entry point | Viền kép, lớn hơn |
| Risk cao | Viền dày |

**Dark mode hoạt động thật.** Mọi màu là CSS custom property; `graphStyle.ts` đọc chúng lúc
runtime nên canvas Cytoscape theo đúng theme của hệ điều hành.

**Kích thước node theo bậc kết nối** — `baseSize + log(degree + 1)`, có chặn trần.

## Thao tác trên graph

| Thao tác | Kết quả |
|---|---|
| Click node | Chi tiết + highlight neighbor trực tiếp |
| Double-click function | Mở CFG |
| Right-click node | Ẩn node |
| Shift + right-click | Expand thêm một hop |
| Hover | Tooltip |
| Kéo / cuộn | Pan / zoom |

## TypeScript

`strict` bật đầy đủ, `noUnusedLocals`, `noUnusedParameters`. Không dùng `any` — metadata chưa
biết kiểu được khai báo `unknown` và narrow tại chỗ dùng.

`cytoscape-fcose` không có type declaration nên có một module declaration tối thiểu ở
`src/types/cytoscape-fcose.d.ts`.
