08 – Constraints & Assumptions

    Constraints (Ràng buộc):
        Phải sử dụng PostgreSQL (đã có sẵn trên server) cho dữ liệu chính.
        Phải sử dụng Apache Kafka cho streaming logs.
        RAG dùng lexical retrieval/BM25-lite và reranking nhẹ để giảm độ phức tạp khi chạy local.
        Không dùng thư viện trả phí trong phần mềm (miễn phí hoặc mã nguồn mở).
        Triển khai: Docker/Kubernetes (theo yêu cầu vận hành).
        API OpenAI/DeepSeek cần key riêng (sẽ cấp trước khi triển khai).
        Latency toàn bộ quá trình ingest -> phân tích -> tạo alert -> dashboard/email enqueue phải < 5 giây trong điều kiện tải MVP.
        UI không hiển thị raw log đầy đủ; chỉ hiển thị log_summary, metadata và extracted_entities đã mask.

    Assumptions (Giả định):
        Người dùng có thể đăng ký công khai, nhưng phải xác thực OTP email trước khi sử dụng hệ thống.
        Hệ thống sẽ tích hợp với các API threat intel có sẵn (NVD, VirusTotal, AbuseIPDB) bằng key/API token cung cấp.
        Dữ liệu logs ban đầu đến từ agent Windows/Ubuntu, email ingest hoặc generic webhook.
        Hệ thống mạng nội bộ cho phép kết nối Kafka và các API bên ngoài.
        Nếu LLM hoặc Threat Intel chậm, hệ thống được phép tạo alert sơ bộ trước rồi enrich bất đồng bộ để vẫn đạt SLA < 5 giây.
