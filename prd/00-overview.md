00 – Tổng quan sản phẩm

    Tên sản phẩm / tính năng: Nền tảng AI-SOC (AI Security Operations Platform)
    Mục tiêu kinh doanh (WHY):
        Giải quyết vấn đề phát hiện và xử lý sự cố an ninh mạng một cách tự động và kịp thời.
        Hỗ trợ các chuyên gia SOC (Security Operations Center) bằng khả năng phân tích logs, mạng lưới tấn công và cảnh báo sử dụng AI.
    Đối tượng người dùng:
        Chuyên gia SOC (nhân viên điều tra an ninh mạng)
        Quản trị viên hệ thống (SOC Admin)
    Phạm vi (Scope):
        In-Scope MVP:
            Xác thực & quản lý người dùng: Public register, OTP qua email, đăng nhập, phân quyền cơ bản.
            Tiếp nhận logs realtime:
                Agent đọc log trực tiếp từ Windows và Ubuntu.
                Email ingest: đọc mail gửi đến một địa chỉ email giám sát.
                Webhook chuẩn chung để nhận log/event từ hệ thống bên ngoài.
                Kafka dùng làm pipeline streaming nội bộ.
            Phân tích logs bằng AI: Tách thông tin, tra cứu MITRE/CVE, gọi API Threat Intelligence, xử lý bằng LLM.
            Dashboard giám sát: Hiển thị alerts, incidents, timeline tấn công, log đã tóm tắt.
            Thông báo alert: Hiển thị trên dashboard và gửi email khi có alert mới.
            Trợ lý ảo (ChatAI): Người dùng có thể đặt câu hỏi an ninh và nhận câu trả lời từ AI.
            Cập nhật dữ liệu Threat Intelligence: Tự động lấy CVE mới, cập nhật MITRE đã embed sẵn.
        Out-of-Scope (Không làm):
            Hiển thị logs raw chi tiết trên UI; UI chỉ hiển thị metadata và bản tóm tắt đã mask thông tin nhạy cảm.
            Tích hợp riêng theo từng SIEM hoặc thiết bị phần cứng SOC; chỉ hỗ trợ webhook chuẩn chung trong MVP.
            Phát triển các mô hình ML mới (chỉ sử dụng model có sẵn và API).
            Upload file log thủ công là optional sau MVP, không phải luồng chính.
    Yêu cầu hiệu năng:
        Latency toàn bộ quá trình từ lúc hệ thống nhận event/log/email đến khi alert xuất hiện trên dashboard và email được enqueue: < 5 giây trong điều kiện tải MVP.
    Tech stack dự kiến:
        Frontend: Next.js (React) với Tailwind CSS (shadcn/ui)
        Backend: Python + FastAPI (RESTful API)
        Cơ sở dữ liệu: PostgreSQL (thành phần lưu dữ liệu chính)
        Vector Database: Qdrant (lưu trữ embedding cho RAG)
        Streaming: Apache Kafka (ingest logs realtime)
        Cache: Redis (lưu kết quả API Threat/AI tạm thời)
        Machine Learning / AI: OpenAI API hoặc DeepSeek cho LLM; Embedding model (OpenAI embeddings hoặc bge-small)
        Triển khai: Docker / Kubernetes; CI/CD (GitHub Actions); Vercel (Frontend) + Railway/Azure (Backend)
