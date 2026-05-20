# AI-SOC MVP

MVP cho realtime ingest log/email, xác thực người dùng bằng OTP qua SMTP Gmail, theo dõi mailbox, và alert trên dashboard.

Hệ thống dùng LLM cloud OpenAI-compatible. Người dùng cấu hình `LLM Base URL`, `LLM Model`, `LLM API Key` trực tiếp trong `Settings` của dashboard; backend và enrichment worker sẽ đọc cấu hình này khi phân tích. Không cần chạy LLM local.

RAG trong phiên bản hiện tại là lexical/BM25-lite retrieval: hệ thống lấy ngữ cảnh từ MITRE/CVE/playbook nội bộ, log/email/alert gần nhất, rồi rerank bằng keyword overlap và IOC matching trước khi gọi LLM.

## Biến môi trường chính

```bash
DATABASE_URL=postgresql+asyncpg://aisoc:aisoc@postgres:5432/aisoc
JWT_SECRET=change-this-secret-before-prod
INGEST_TOKEN=local-ingest-token
INTERNAL_TOKEN=local-internal-token
CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:8000","http://127.0.0.1:8000"]

SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USERNAME=ninhvanquyen2020@gmail.com
SMTP_PASSWORD=your-gmail-app-password
SMTP_FROM=ninhvanquyen2020@gmail.com

# IMAP có thể cấu hình trực tiếp trong Settings -> IMAP đọc mailbox.
# Các biến dưới đây chỉ là fallback khi chưa lưu cấu hình từ UI.
IMAP_HOST=imap.gmail.com
IMAP_USER=ninhvanquyen2020@gmail.com
IMAP_PASSWORD=your-gmail-app-password
IMAP_FOLDER=INBOX
IMAP_BACKFILL_LIMIT=50
```

Các biến `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` chỉ là fallback local. Cách dùng chính là nhập trên giao diện `Settings -> Cloud LLM API`.

## Chạy local

```bash
cd frontend
npm install
npm run build
cd ..
docker compose --profile integrations up --build api frontend postgres redis email-ingest
```

Mở `http://localhost:3000`.

Lưu ý: SMTP chỉ dùng để gửi OTP/thông báo. SMTP/IMAP có thể nhập trong `Settings` sau khi đăng nhập; hệ thống lưu vào runtime config trong database. Muốn dashboard đọc và hiển thị email trong mailbox thì phải chạy service `email-ingest`. Sau khi đổi IMAP, restart `email-ingest` để backfill lại mail cũ.

Với Gmail, `SMTP_PASSWORD` và `IMAP_PASSWORD` phải là **App Password** của đúng tài khoản mailbox. Nếu `email-ingest` log `AUTHENTICATIONFAILED`, kiểm tra lại các điểm sau: Gmail đã bật IMAP trong `Settings -> Forwarding and POP/IMAP`, App Password thuộc đúng email trong `IMAP_USER`, app password chưa bị revoke, và không dùng mật khẩu đăng nhập Google thường.

## Luồng xác thực

1. Đăng ký: nhập email + password, hệ thống gửi OTP qua SMTP.
2. Đăng nhập: nhập email + password, hệ thống gửi OTP đăng nhập qua SMTP.
3. Xác thực mailbox IMAP: nhập `IMAP User` trong `Settings`, hệ thống gửi OTP tới chính email đó. `email-ingest` chỉ đọc mailbox khi `IMAP User` đã xác thực.
4. Xác thực email nhận alert: nhập email nhận thông báo trong `Settings`, hệ thống gửi OTP qua SMTP.

## Realtime mail/log + alert

- Khi email ingest vào hệ thống, dashboard hiển thị realtime trong `Logs & Email`.
- `Dashboard` có panel `Mailbox IMAP đã nhận`, lọc theo `IMAP User` đã xác thực OTP.
- Sau khi xác thực OTP cho `IMAP User`, UI sẽ hiển thị các email đã được ingest trước đó nếu chúng match `From`, `To/Cc/Bcc`, `Delivered-To`, hoặc mailbox label. Email ingest cũng backfill một lần các mail gần nhất khi service khởi động (`IMAP_BACKFILL_LIMIT`, mặc định 50), sau đó tiếp tục polling mail mới `UNSEEN`.
- Nếu mailbox đã có mail cũ nhưng chưa từng được email-ingest đọc vào hệ thống, cần restart `email-ingest` hoặc tăng `IMAP_BACKFILL_LIMIT` rồi chạy lại service để backfill.
- Nếu phát hiện dấu hiệu nghi vấn, hệ thống tạo alert và hiển thị trên dashboard.
