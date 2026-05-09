05 – API Spec & Tích hợp bên thứ ba

    Auth: Xác thực JWT; OAuth2 để sau MVP
        POST /auth/login – Request: {email, password}, Response: {token, user}.
        POST /auth/register – Request: {email, password}, Response: {user, otp_required}.
        POST /auth/verify-otp – Request: {email, otp, purpose}, Response: {token, user}.
        POST /auth/resend-otp – Request: {email, purpose}, Response: {ok}.
    Users (Admin):
        GET /users – Lấy danh sách người dùng (Admin only).
        POST /users – Tạo tài khoản mới.
        PATCH /users/{id}/role – Cập nhật role (Admin only).
    Collectors:
        POST /collectors/register – Agent đăng ký host Windows/Ubuntu.
        POST /collectors/heartbeat – Agent gửi trạng thái online/offline.
        POST /collectors/events – Agent gửi batch event/log đã chuẩn hóa.
        GET /collectors – Danh sách collector và trạng thái.
    Ingest:
        POST /ingest/webhook – Nhận event/log JSON qua webhook chuẩn chung.
        POST /ingest/email/test – Kiểm tra cấu hình mailbox ingest.
    Logs:
        GET /logs – Lấy danh sách logs đã tóm tắt (theo user, time, source, source_type).
        GET /logs/{id} – Chi tiết metadata, log_summary và extracted_entities; không trả raw log cho UI.
    Alerts:
        GET /alerts – Lấy danh sách cảnh báo (theo mức độ, ngày, tình trạng).
        GET /alerts/{id} – Chi tiết cảnh báo.
        PATCH /alerts/{id} – Cập nhật status, severity, message.
        POST /alerts/{id}/tags – Gắn tag cho alert.
        DELETE /alerts/{id}/tags/{tag_id} – Gỡ tag khỏi alert.
    Incidents:
        GET /incidents – Lấy danh sách sự cố.
        GET /incidents/{id} – Chi tiết incident (các alert liên quan).
        POST /incidents – Tạo incident từ alert hoặc thủ công.
        PATCH /incidents/{id} – Cập nhật status, severity, description.
        POST /incidents/{id}/alerts – Thêm alert vào incident.
        POST /incidents/{id}/tags – Gắn tag cho incident.
    AI Assistant:
        POST /assistant/query – Gửi câu hỏi cho AI (body: {question, context}), Response: {answer}.
    Intel Sources:
        GET /intel-sources – Danh sách nguồn Threat Intel.
        POST /intel-sources – Tạo/cấu hình nguồn Threat Intel.
        PATCH /intel-sources/{id} – Bật/tắt hoặc cập nhật cấu hình.
    Notifications:
        GET /notifications – Lịch sử gửi email alert.
        POST /notifications/test-email – Gửi email test.
    Tích hợp bên thứ ba:
        Threat Intelligence APIs:
            AbuseIPDB API (lookup IP reputation)
            VirusTotal API (scan domain/URL/sha256)
            NVD API (CVE search bằng từ khóa phần mềm/version)
        Email/Notifications:
            SendGrid hoặc AWS SES (gửi email cảnh báo cho user/admin).
            Slack Webhook để sau MVP.
        Storage:
            Cloudflare R2 hoặc local object storage (lưu raw log/attachment nếu cần truy vết).
        Webhook nhận:
            Hỗ trợ webhook chuẩn chung với token/chữ ký; không xây adapter riêng cho Splunk/Graylog trong MVP.
