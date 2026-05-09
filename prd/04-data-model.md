04 – Mô hình dữ liệu (Data Model / Schema)

    Bảng users:
        id (UUID, PK)
        email (String, unique, not null)
        password_hash (String, not null)
        role (Enum: soc_analyst, admin)
        is_email_verified (Boolean)
        failed_login_count (Integer)
        locked_until (Timestamp, nullable)
        created_at (Timestamp)

    Bảng otp_tokens:
        id (UUID, PK)
        user_id (UUID, FK → users.id)
        otp_hash (String)
        purpose (Enum: register, login, reset_password)
        expires_at (Timestamp)
        consumed_at (Timestamp, nullable)

    Bảng collectors:
        id (UUID, PK)
        host_name (String)
        os_type (Enum: windows, ubuntu)
        agent_version (String)
        status (Enum: online, offline, degraded)
        last_seen_at (Timestamp)
        created_at (Timestamp)

    Bảng logs:
        id (UUID, PK)
        user_id (UUID, FK → users.id, nullable) – user liên quan nếu có
        collector_id (UUID, FK → collectors.id, nullable)
        source_type (Enum: windows_agent, ubuntu_agent, email, webhook)
        source (String) – nguồn log (e.g. “Windows Security”, “journalctl”, “mailbox”, “webhook”)
        content_ref (String, nullable) – liên kết raw log trong storage nếu cần lưu
        log_summary (Text) – bản tóm tắt đã mask thông tin nhạy cảm để hiển thị UI
        extracted_entities (JSONB) – IP, user, domain, hash, process, file path...
        correlation_id (String)
        received_at (Timestamp) – thời gian log được hệ thống tiếp nhận

    Bảng alerts:
        id (UUID, PK)
        log_id (UUID, FK → logs.id) – log liên quan
        severity (Enum: Low, Medium, High, Critical)
        status (Enum: open, investigating, resolved, false_positive)
        message (String) – mô tả cảnh báo
        ai_summary (Text)
        rule_name (String, nullable)
        detected_at (Timestamp) – thời gian phát hiện
        created_by (UUID, FK → users.id, nullable) – user tạo thủ công; null nếu hệ thống tạo tự động

    Bảng incidents:
        id (UUID, PK)
        name (String) – tiêu đề sự cố (e.g. “Brute Force Attack May 2026”)
        description (Text) – mô tả chi tiết
        severity (Enum: Low, Medium, High, Critical)
        status (Enum: open, investigating, resolved, false_positive)
        created_at (Timestamp)

    Bảng incident_alerts: (quan hệ many-to-many)
        incident_id (UUID, FK → incidents.id)
        alert_id (UUID, FK → alerts.id)

    Bảng tags:
        id (UUID, PK)
        name (String, unique)
        color (String)

    Bảng alert_tags:
        alert_id (UUID, FK → alerts.id)
        tag_id (UUID, FK → tags.id)

    Bảng incident_tags:
        incident_id (UUID, FK → incidents.id)
        tag_id (UUID, FK → tags.id)

    Bảng email_messages:
        id (UUID, PK)
        message_id (String, unique)
        mailbox (String)
        sender (String)
        recipients (JSONB)
        subject (String)
        body_summary (Text)
        attachment_metadata (JSONB)
        received_at (Timestamp)

    Bảng intel_sources:
        id (UUID, PK)
        name (String)
        type (Enum: nvd, virustotal, abuseipdb, mitre)
        enabled (Boolean)
        config_encrypted (JSONB)
        updated_at (Timestamp)

    Bảng notifications:
        id (UUID, PK)
        alert_id (UUID, FK → alerts.id)
        channel (Enum: email)
        recipient (String)
        status (Enum: queued, sent, failed)
        created_at (Timestamp)
        sent_at (Timestamp, nullable)

    Bảng ai_queries: (Lưu lịch sử hỏi đáp với AI)
        id (UUID, PK)
        user_id (UUID, FK → users.id)
        question (Text)
        response (Text)
        asked_at (Timestamp)

    Quan hệ:
        1 người dùng users có thể liên quan đến nhiều logs và tạo nhiều alerts thủ công.
        1 collector có thể gửi nhiều logs.
        1 log có thể sinh nhiều alerts.
        1 incident tổng hợp nhiều alerts.
        1 alert/incident có thể có nhiều tags.
