06 – UI/UX Requirements

    Thiết kế hệ thống: Sử dụng Tailwind CSS + shadcn/ui cho component.
    Màu chính: Xanh dương #2563EB (Blue-600), màu nhấn #1E40AF (Blue-800).
    Font chữ: Inter (tích hợp sẵn trên web).
    Responsive breakpoints:
        Mobile: 375px (iPhone)
        Tablet: 768px
        Desktop: 1280px và lớn hơn
    Layout:
        Dashboard hiển thị sidebar menu, các card Alert/Incident summary, timeline attack, bảng log_summary.
        Alerts mới xuất hiện realtime trên dashboard và có trạng thái gửi email notification.
        Trang Collectors hiển thị Windows/Ubuntu agent, status, last_seen_at, host_name.
        Trang Email Ingest hiển thị mailbox, trạng thái kết nối, lần đọc mail gần nhất.
        Form & modals: login form, register form, OTP form, query AI, tag/status update.
    Trạng thái cần xử lý:
        Loading: Hiện spinner khi chờ API (ví dụ: phân tích log, truy vấn AI).
        Empty state: Báo “Không có dữ liệu” khi không có alert/incidents/logs.
        Error: Hiển thị thông báo lỗi rõ ràng (toast/banners) nếu request thất bại.
        Success: Xác nhận (toasts/modal) khi hành động thành công (ví dụ: collector online, email ingest test thành công, câu hỏi AI trả lời xong).
