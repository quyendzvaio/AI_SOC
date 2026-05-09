Dự án sinh ra để đọc log trực tiếp của Windows/Ubuntu và đọc các mail được gửi đến một địa chỉ email realtime.
MVP hỗ trợ thêm generic webhook ingest để nhận event/log JSON từ hệ thống bên ngoài.
System latency mục tiêu: <5s cho toàn bộ quá trình từ ingest đến khi alert hiển thị trên dashboard và email notification được enqueue.
Định dạng log hợp lệ: .log, .txt, .evtx, syslog Ubuntu dạng text, Systemd Journal đọc qua journalctl rồi chuẩn hóa thành event JSON.
UI chỉ hiển thị log đã summarized/masked, không hiển thị raw log đầy đủ.
