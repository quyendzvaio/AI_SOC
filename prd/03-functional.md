03 – Yêu Cầu Chức Năng (Functional Requirements)
ID	Tính năng	Mức độ ưu tiên	Ghi chú
F01	Đăng nhập/Đăng ký public (email & password)	Must-have	Validation email/password, OTP qua email; OAuth để sau MVP
F02	Phân quyền người dùng (role: SOC Analyst/Admin)	Must-have	Quản lý quyền truy cập hệ thống
F03	Collector Agent Windows/Ubuntu	Must-have	Đọc Windows Event Log, .evtx, .log, .txt, syslog Ubuntu và Systemd Journal qua journalctl
F04	Phân tích logs/email/event tự động	Must-have	Tích hợp Kafka, RAG, Threat Intel, LLM; alert đầu tiên trong <5s
F05	Xem Dashboard báo cáo Alerts & Incidents	Must-have	Hiển thị bảng điều khiển trực quan
F06	Tính năng Chat với Trợ lý AI	Should-have	Hỏi/đáp về mối đe dọa, logs
F07	Quản lý nguồn Intel (MITRE, NVD API keys)	Should-have	Cấu hình thêm/bớt nguồn dữ liệu
F08	Thông báo Email khi có alert mới	Must-have	Gửi cảnh báo realtime qua email; Slack để sau MVP
F09	Tìm kiếm logs, alerts, incidents	Should-have	Cho phép query theo time/user/mức độ
F10	Quản lý người dùng (CRUD tài khoản)	Nice-to-have	Giao diện Admin để thêm/xóa user
F11	Xuất báo cáo logs/alerts (CSV/PDF)	Nice-to-have	Hỗ trợ trích xuất dữ liệu cơ bản
F12	Email ingest	Must-have	Đọc mailbox giám sát, parse header/body/attachment metadata, trích xuất IOC
F13	Generic webhook ingest	Must-have	Nhận event/log JSON qua webhook có xác thực chữ ký hoặc token
F14	Tag và status workflow	Must-have	Tag alert/incident; status open, investigating, resolved, false_positive
