02 – Luồng Nghiệp Vụ (Flows)
Flow 1: Đăng nhập hệ thống

    Người dùng mở giao diện đăng nhập.
    Người dùng có thể đăng ký công khai bằng email/password.
    Khi đăng ký, hệ thống gửi OTP qua email; tài khoản chỉ active sau khi OTP hợp lệ.
    Người dùng nhập email và mật khẩu, hoặc đăng nhập bằng Google/OAuth (nếu kích hoạt sau MVP).
    Hệ thống kiểm tra thông tin:
        Nếu hợp lệ: Chuyển đến trang dashboard.
        Nếu sai thông tin: Hiển thị thông báo lỗi "Sai thông tin đăng nhập".
    Edge Case: Nhập sai 3 lần; khóa tài khoản tạm thời 15 phút và hiện thông báo.

Flow 2: Ingest realtime và Phân tích Logs

    Nguồn dữ liệu MVP:
        Windows Agent đọc Windows Event Logs và file .log/.txt được cấu hình.
        Ubuntu Agent đọc file .log/.txt, syslog và Systemd Journal thông qua journalctl.
        Email Ingest đọc mailbox giám sát để phân tích email, header, body và attachment metadata.
        Generic Webhook nhận event/log JSON từ hệ thống bên ngoài.
    Định dạng log hợp lệ:
        .log, .txt, .evtx.
        Syslog Ubuntu dạng text.
        Systemd Journal được đọc qua journalctl và chuẩn hóa thành event JSON.
    Agent hoặc ingest service chuẩn hóa dữ liệu, thêm source_type, host, received_at, correlation_id.
    Backend nhận event, kiểm tra schema và đẩy vào Kafka topic security_events.

Backend xác thực event:

    Nếu hợp lệ: Ghi metadata vào PostgreSQL và đẩy event vào Kafka topic security_events.
    Nếu không hợp lệ: Trả lỗi “Định dạng event/log không hợp lệ”.

AI Worker (Kafka consumer) lấy messages từ topic:

    Xử lý tách trường (IP, user, action...), chuẩn hóa log.
    Gọi API Threat Intelligence (AbuseIPDB, VirusTotal, NVD) theo thực thể trích được.
    Truy hồi ngữ cảnh bằng lexical retrieval/BM25-lite từ MITRE, playbook, CVE hints và log/email/alert gần nhất.
    Tập hợp ngữ cảnh cho LLM (log + MITRE + CVE + reputation).
    Gửi prompt đến LLM, nhận kết quả phân tích.

Nếu mức độ nguy hiểm vượt ngưỡng:

    Tự động tạo một Alert trong DB (PostgreSQL).
    Nếu liên quan nhiều alert tương tự, gộp thành Incident.
    Alert mới được hiển thị trên dashboard realtime.
    Hệ thống enqueue email notification cho người dùng/admin liên quan.

Kết thúc trong mục tiêu latency < 5 giây từ lúc nhận event đến lúc alert hiển thị trên dashboard và email notification được enqueue.
Edge Case Luồng 2:

    Agent mất kết nối: Hiển thị trạng thái collector offline và ghi nhận last_seen_at.
    Mailbox không truy cập được: Hiển thị lỗi cấu hình email ingest và retry theo backoff.
    Webhook sai schema hoặc thiếu chữ ký: Trả lỗi 400/401.
    Hết hàng (CPU/queue đầy): Backpressure Kafka hoặc trả về "Hệ thống đang quá tải, thử lại sau".
    Nếu LLM hoặc API Threat Intel chậm: Tạo alert sơ bộ khi đủ tín hiệu, sau đó enrich AI bất đồng bộ nhưng vẫn phải đảm bảo alert đầu tiên trong < 5 giây.

Flow 3: Trò chuyện với Trợ lý AI

    Người dùng mở mục Trợ lý ảo trong Dashboard.
    Nhập câu hỏi hoặc thông tin cần tra cứu (ví dụ: “Địa chỉ IP 1.2.3.4 có nguy hiểm không?”).
    Hệ thống lấy input, chuyển vào quy trình RAG nhẹ:
        Tokenize truy vấn, truy hồi ngữ cảnh bằng keyword overlap/BM25-lite từ MITRE, playbook, CVE hints và telemetry gần nhất.
        Rerank kết quả bằng keyword overlap và IOC matching.
        Có thể gọi thêm API nếu cần (ví dụ: AbuseIPDB tìm IP).
        Soạn prompt với ngữ cảnh bổ sung.
        Gửi sang LLM để trả lời.
    Nhận kết quả AI trả về, hiển thị cho người dùng.
    Lưu lịch sử câu hỏi và trả lời vào DB.

Edge Case Luồng 3:

    Nội dung câu hỏi không hợp lệ: (Ví dụ: rỗng) → yêu cầu nhập lại.
    LLM timeout hoặc lỗi: Thông báo “Đang có lỗi, vui lòng thử lại sau”.

Flow 4: Xem Alert và Incident

    Trong Dashboard, người dùng chuyển đến mục Alerts.
    Hệ thống hiển thị danh sách alert với trạng thái (mức độ, ngày tạo).
    Người dùng chọn một alert, xem chi tiết (log liên quan, phân tích AI).
    UI hiển thị log_summary, extracted_entities và metadata; không hiển thị raw log đầy đủ.
    Người dùng có thể chuyển alert thành Incident (tự động gộp hoặc tùy chỉnh).
    Trong mục Incidents, hiển thị timeline các alert liên quan, tiến trình xử lý.
    Người dùng có thể cập nhật status, severity và tag cho alert/incident.

Edge Case Luồng 4:

    Không có alert nào: Hiển thị trang rỗng với thông báo "Không có cảnh báo mới".
