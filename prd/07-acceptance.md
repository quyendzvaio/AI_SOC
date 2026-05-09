07 – Acceptance Criteria

    Feature: Đăng nhập
        ✅ Given người dùng nhập đúng email & password,
        When bấm “Đăng nhập”,
        Then redirect về /dashboard, hiển thị tên user (và API trả token).
        ✅ Given người dùng đăng ký public bằng email/password,
        When nhập OTP hợp lệ được gửi qua email,
        Then tài khoản được active và có thể đăng nhập.
        ❌ Given người dùng nhập sai password 3 lần liên tiếp,
        When bấm “Đăng nhập”,
        Then khóa tài khoản 15 phút, hiển thị thông báo “Sai quá nhiều lần, tài khoản bị khóa tạm thời”.

    Feature: Realtime Ingest và Phân tích Log
        ✅ Given người dùng đã đăng nhập,
        When Windows/Ubuntu agent gửi log hợp lệ,
        Then hệ thống bắt đầu phân tích, tạo alert nếu có, alert xuất hiện trên dashboard trong < 5 giây.
        ✅ Given email ingest nhận email có IOC đáng ngờ,
        When hệ thống phân tích xong,
        Then alert xuất hiện trên dashboard và email notification được enqueue trong < 5 giây.
        ✅ Given webhook nhận event JSON hợp lệ,
        When hệ thống xác thực token/chữ ký thành công,
        Then event được đẩy vào Kafka và phân tích.
        ❌ Given log/event không đúng schema hoặc định dạng không hỗ trợ,
        When ingest,
        Then hiện lỗi “Định dạng event/log không hợp lệ”.
        ❌ Given collector không gửi heartbeat,
        When quá ngưỡng timeout,
        Then collector hiển thị trạng thái offline.

    Feature: Chat AI Assistant
        ✅ Given người dùng nhập câu hỏi hợp lệ (không rỗng),
        When gửi câu hỏi,
        Then nhận được câu trả lời từ AI và hiển thị trên màn hình.
        ❌ Given hệ thống đang phân tích AI hoặc API bị lỗi,
        When gửi câu hỏi,
        Then hiển thị thông báo lỗi “AI hiện không phản hồi, vui lòng thử lại sau”.

    Feature: Xem Alert
        ✅ Given có ít nhất một alert mới,
        When người dùng vào trang Alerts,
        Then danh sách alert hiện ra có alert đó, hiển thị mức độ và thời gian.
        ✅ Given người dùng mở chi tiết alert,
        When hệ thống trả dữ liệu,
        Then UI hiển thị log_summary, extracted_entities, ai_summary và không hiển thị raw log đầy đủ.
        ✅ Given người dùng cập nhật status hoặc tag,
        When thao tác thành công,
        Then alert/incident hiển thị status/tag mới.
        ❌ Given không có alert mới,
        When vào trang Alerts,
        Then hiển thị thông báo “Không có cảnh báo mới”.
