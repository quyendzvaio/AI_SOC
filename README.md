# AI-SOC MVP

MVP cho realtime ingest log/email, xác thực người dùng bằng OTP qua SMTP Gmail, theo dõi mailbox, và alert trên dashboard.

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
```

## Chạy local

```bash
cd frontend
npm install
npm run build
cd ..
docker compose up --build api frontend postgres redis
```

Mở `http://localhost:3000`.

## Luồng xác thực

1. Đăng ký: nhập email + password, hệ thống gửi OTP qua SMTP.
2. Đăng nhập: nhập email + password, hệ thống gửi OTP đăng nhập qua SMTP.
3. Xác thực email theo dõi: nhập email theo dõi trong `Settings`, hệ thống gửi OTP qua SMTP.

## Realtime mail/log + alert

- Khi email ingest vào hệ thống, dashboard hiển thị realtime trong `Logs & Email`.
- `Dashboard` có panel `Mail theo dõi đã nhận` (lọc theo email theo dõi đã xác thực).
- Nếu phát hiện dấu hiệu nghi vấn, hệ thống tạo alert và hiển thị trên dashboard.
