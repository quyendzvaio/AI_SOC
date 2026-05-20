# Chương 4: Triển khai hệ thống AI_SOC

Trong chương này, chúng tôi trình bày quá trình phát triển và triển khai hệ thống AI_SOC phục vụ giám sát log và email bằng AI. Phiên bản hiện tại của hệ thống tập trung vào mục tiêu MVP: thu thập log/email gần thời gian thực, chuẩn hóa dữ liệu, tạo cảnh báo an ninh, cung cấp trợ lý AI cho chuyên viên SOC, và cho phép cấu hình LLM cloud trực tiếp trên giao diện. Hệ thống sử dụng RAG dạng lexical/BM25-lite kết hợp dữ liệu telemetry gần nhất và tri thức nội bộ về MITRE/CVE/playbook, không sử dụng Qdrant hay vector database trong phiên bản cuối.

## 4.1 Phân tích yêu cầu hệ thống

AI_SOC được xây dựng để hỗ trợ chuyên viên SOC phát hiện sớm rủi ro an ninh mạng từ hai nguồn dữ liệu chính: log hệ thống và email. Log có thể đến từ Windows Event Logs, file `.log`, `.txt`, `.evtx`, syslog Ubuntu hoặc Systemd Journal được đọc thông qua `journalctl`. Email được đọc từ mailbox IMAP sau khi người dùng cấu hình và xác thực OTP cho địa chỉ mailbox đó. Ngoài ra, hệ thống hỗ trợ webhook chuẩn chung để các hệ thống bên ngoài gửi event/log JSON vào backend.

Về chức năng, hệ thống cần đáp ứng các nhóm yêu cầu sau:

1. Xác thực người dùng bằng email/password và OTP qua SMTP.
2. Cho phép cấu hình SMTP, IMAP, LLM Base URL, LLM Model và LLM API Key trực tiếp trên giao diện Settings.
3. Thu thập log từ agent Windows/Ubuntu, email từ IMAP và event từ webhook.
4. Chuẩn hóa log/email thành metadata, `log_summary`, `body_summary`, entity trích xuất và mức rủi ro.
5. Phân tích bằng rule/heuristic, Threat Intelligence API và LLM cloud OpenAI-compatible.
6. Thực hiện RAG nhẹ bằng lexical retrieval/BM25-lite trên tri thức nội bộ và telemetry gần nhất.
7. Hiển thị log/email/alert realtime trên dashboard.
8. Gửi email cảnh báo đến địa chỉ nhận alert đã xác thực OTP.

Về phi chức năng, phiên bản MVP đặt mục tiêu alert đầu tiên xuất hiện trên dashboard và email notification được enqueue trong dưới 5 giây trong điều kiện tải thử nghiệm. Các bước nặng hơn như gọi LLM cloud, Threat Intelligence hoặc enrichment có thể thực hiện bất đồng bộ để tránh làm nghẽn API chính. Hệ thống không lưu plain text secret trong database; các runtime secret như API key, SMTP/IMAP password được lưu qua cơ chế mã hóa runtime config.

Khác với bản thiết kế ban đầu, phiên bản hiện tại không triển khai vector embedding và không sử dụng Qdrant. Lý do là mục tiêu hiện tại ưu tiên chạy local gọn nhẹ, dễ cài đặt và dễ kiểm thử. Vì vậy, RAG được triển khai theo hướng truy hồi lexical: tách từ khóa, so khớp IOC như IP/domain/hash, chấm điểm overlap và rerank kết quả.

## 4.2 Thiết kế kiến trúc AI_SOC

Kiến trúc AI_SOC hiện tại gồm các thành phần chính:

| Thành phần | Công nghệ | Vai trò |
|---|---|---|
| Frontend | Next.js 16, React, CSS/Tailwind-style UI | Dashboard, realtime log/email/alert, Settings, Assistant Chat |
| Backend API | FastAPI, SQLAlchemy async | Auth, ingest, runtime config, logs, emails, alerts, assistant |
| Database | PostgreSQL 16 | Lưu users, OTP, runtime settings, logs, emails, alerts, incidents |
| Email ingest | Python, FastAPI service, `imaplib` | Đọc mailbox IMAP, backfill mail cũ, polling mail mới |
| Collector agent | Python | Đọc log Windows/Ubuntu, file log và Systemd Journal |
| Kafka | Apache Kafka, trong compose full | Streaming security event cho enrichment worker |
| Enrichment worker | Python, aiokafka | Consumer Kafka, enrich event bằng Threat Intel/LLM |
| Redis | Redis Alpine | Thành phần cache/queue dự phòng trong kiến trúc local |
| LLM | Cloud OpenAI-compatible | Phân tích ngữ cảnh, reasoning, khuyến nghị xử lý |
| RAG | Lexical/BM25-lite | Truy hồi MITRE/CVE/playbook và telemetry gần nhất |

Luồng tổng quát của hệ thống là:

```text
Agent/Webhook/Email Ingest
        -> FastAPI Backend
        -> PostgreSQL
        -> Kafka/Enrichment Worker nếu chạy full profile
        -> Threat Intel + Lexical RAG + Cloud LLM
        -> Alert/Incident
        -> Dashboard realtime + Email notification
```

Trong cấu hình local cơ bản, người dùng có thể chạy API, frontend, PostgreSQL, Redis và email-ingest. Với cấu hình đầy đủ hơn, `docker-compose.full.yml` bổ sung Kafka và enrichment-worker để mô phỏng pipeline event-driven.

Điểm quan trọng của kiến trúc hiện tại là tách service theo miền chức năng. API không chứa toàn bộ logic ingest nặng; email-ingest và collector-agent là service riêng. Điều này giúp image API nhẹ hơn, giảm thời gian khởi động và dễ kiểm thử từng phần.

## 4.3 Xây dựng hệ thống Backend

Backend được xây dựng bằng FastAPI và tổ chức theo các router/service riêng. Một số nhóm API chính gồm:

| Nhóm API | Endpoint tiêu biểu | Chức năng |
|---|---|---|
| Auth | `/auth/register`, `/auth/login`, `/auth/verify-otp` | Đăng ký, đăng nhập và xác thực OTP |
| Collectors | `/collectors/register`, `/collectors/heartbeat`, `/collectors/events` | Agent đăng ký, heartbeat và gửi log batch |
| Ingest | `/ingest/webhook` | Nhận event/log JSON từ hệ thống ngoài |
| Logs | `/logs`, `/logs/{id}` | Truy vấn log đã tóm tắt và metadata |
| Emails | `/emails`, `/emails/mailbox` | Truy vấn email ingest và email thuộc mailbox IMAP đã xác thực |
| Alerts | `/alerts`, `/alerts/{id}` | Xem/cập nhật cảnh báo |
| Settings | `/settings/runtime-config` | Lưu cấu hình SMTP/IMAP/LLM/Threat Intel runtime |
| IMAP OTP | `/settings/imap-email/otp`, `/settings/imap-email/verify` | Xác thực mailbox IMAP trước khi đọc mail |
| Assistant | `/assistant/query`, `/assistant/history` | Hỏi trợ lý AI và lưu lịch sử |
| Knowledge | `/knowledge/search` | Tìm ngữ cảnh trong knowledge base lexical |
| Internal | `/internal/runtime-config` | Service nội bộ lấy runtime config |

Backend dùng PostgreSQL làm nguồn lưu trữ chính. Các dữ liệu nhạy cảm trong runtime settings như LLM API key, SMTP password, IMAP password được lưu dưới dạng secret đã mã hóa, không trả lại plain text cho frontend. Với IMAP, backend chỉ cho email-ingest đọc mailbox sau khi `imap_user` được xác thực bằng OTP gửi tới chính mailbox đó.

Về phân tích an ninh, backend có các service chính:

- `knowledge_base.py`: chứa knowledge base nội bộ về MITRE, CVE hints và playbook; thực hiện truy hồi lexical/BM25-lite.
- `assistant_live.py`: lấy alert/log/email gần nhất, truy hồi knowledge, rerank theo keyword/IOC, gọi Threat Intelligence API và LLM cloud để trả lời câu hỏi SOC.
- `detection.py`, `analyzer.py`, `correlation_service.py`: hỗ trợ nhận diện dấu hiệu bất thường, severity, correlation và alert.
- `smtp_mail.py`: gửi OTP và email thông báo qua SMTP.
- `runtime_config.py`, `crypto.py`: quản lý cấu hình runtime và secret.

## 4.4 Xây dựng hệ thống Frontend

Frontend được phát triển bằng Next.js 16 và React. Giao diện hiện tại gồm các khu vực chính:

1. Dashboard tổng quan: hiển thị thống kê alert, log, email và trạng thái hệ thống.
2. Logs & Email: hiển thị log/event và email đã ingest theo thời gian gần thực.
3. Alerts & Incidents: hiển thị cảnh báo, mức độ nghiêm trọng, trạng thái xử lý và phân loại.
4. Trợ lý AI: cho phép người dùng hỏi về alert, log, IP, domain hoặc tình huống an ninh.
5. Settings: cấu hình Cloud LLM API, SMTP gửi OTP/alert, IMAP đọc mailbox, email nhận alert và xác thực OTP.

Frontend gọi backend thông qua `NEXT_PUBLIC_API_BASE_URL`. Khi chạy local, biến này trỏ về `http://localhost:8000`. Dashboard không hiển thị raw log đầy đủ để giảm rủi ro lộ thông tin nhạy cảm; thay vào đó, giao diện hiển thị summary, metadata và extracted entities.

Một điểm được điều chỉnh trong phiên bản cuối là bỏ khái niệm "email cần theo dõi" tách biệt. Hệ thống hiện sử dụng trực tiếp IMAP User làm mailbox cần đọc. Người dùng cấu hình IMAP Host, Port, User, App Password, Folder và Backfill Limit, sau đó xác thực OTP cho IMAP User. Khi xác thực thành công và service email-ingest chạy, dashboard sẽ hiển thị các mail đã được ingest từ mailbox đó.

## 4.5 Tích hợp LLM và RAG

Phiên bản hiện tại sử dụng LLM cloud OpenAI-compatible thay vì LLM local. Người dùng có thể cấu hình `LLM Base URL`, `LLM Model` và `LLM API Key` trực tiếp trong Settings. Ví dụ, hệ thống có thể dùng OpenAI API hoặc DeepSeek API nếu endpoint tương thích chuẩn `/chat/completions`.

Cơ chế RAG trong hệ thống là lexical/BM25-lite, gồm các bước:

1. Tokenize câu hỏi, log hoặc email.
2. Trích xuất IOC như IP, domain và hash.
3. Truy hồi knowledge nội bộ từ MITRE/CVE/playbook bằng keyword overlap.
4. Lấy thêm log, email và alert gần nhất trong PostgreSQL.
5. Rerank tài liệu theo overlap và mức khớp IOC.
6. Gọi thêm Threat Intelligence API nếu có IP/domain/CVE hint.
7. Ghép context vào prompt và gửi sang LLM.

Do không sử dụng vector embedding, hệ thống không cần Qdrant, không cần embedding model và không cần job upsert vector. Cách tiếp cận này phù hợp với MVP chạy local vì giảm tài nguyên, giảm số service phải vận hành và vẫn giữ được lợi ích RAG ở mức thực dụng: LLM có thêm ngữ cảnh từ MITRE/playbook/telemetry thay vì chỉ trả lời dựa trên kiến thức nội tại.

Kết quả trả về từ LLM được dùng để hỗ trợ chuyên viên SOC: giải thích mức rủi ro, nêu bằng chứng, phân loại kỹ thuật tấn công và đề xuất hành động tiếp theo như bật MFA, chặn IP, kiểm tra endpoint, hoặc cô lập email nghi vấn.

## 4.6 Xử lý log và email phục vụ phân tích an ninh mạng

### 4.6.1 Xử lý log

Collector-agent có nhiệm vụ đọc log từ hệ thống. Trên Ubuntu, agent có thể đọc file log như `/var/log/auth.log`, `/var/log/syslog` và Systemd Journal qua `journalctl`. Trên Windows, agent có thể đọc Windows Event Logs hoặc file `.evtx` tùy cấu hình. Các log được chuẩn hóa thành event JSON trước khi gửi về backend.

Backend nhận event, kiểm tra schema, lưu metadata vào PostgreSQL và tạo alert nếu phát hiện dấu hiệu đáng ngờ. Ví dụ:

- Nhiều lần đăng nhập SSH thất bại trong thời gian ngắn: nghi brute force, liên quan MITRE T1110.
- Login admin bất thường sau nhiều lần failed login: nghi valid account abuse.
- URL chứa pattern SQL Injection như `' OR 1=1 --`: nghi web attack.
- Tải file `.exe` từ domain không rõ: nghi malware download.

Các log hiển thị trên dashboard ở dạng tóm tắt, có source, severity, extracted entities và thời gian nhận.

### 4.6.2 Xử lý email

Email-ingest là service riêng đọc mailbox qua IMAP. Service này ưu tiên lấy cấu hình IMAP từ backend thông qua `/internal/runtime-config`; nếu chưa có runtime config thì dùng biến môi trường fallback. Để đảm bảo quyền truy cập hợp lệ, service chỉ bắt đầu polling khi IMAP User đã được xác thực OTP.

Khi khởi động, email-ingest có thể backfill một số email gần nhất theo `IMAP_BACKFILL_LIMIT`, sau đó tiếp tục polling email mới. Email được parse thành các trường như mailbox, sender, recipients, subject, body summary và attachment metadata. Hệ thống phân tích các dấu hiệu như:

- Tiêu đề yêu cầu đổi mật khẩu hoặc xác minh tài khoản khẩn cấp.
- URL nghi vấn, domain lạ hoặc domain có TLD rủi ro.
- Attachment thực thi như `.exe`, `.scr`, `.bat`.
- Nội dung spam hoặc social engineering.

Nếu email có rủi ro cao, hệ thống tạo alert và hiển thị trên dashboard. Nếu email nhận alert đã được cấu hình và xác thực, hệ thống gửi thông báo qua SMTP.

## 4.7 Triển khai bằng Docker Compose local

Phiên bản cuối của AI_SOC ưu tiên chạy local bằng Docker Compose, không yêu cầu VPS hay CI/CD production. Cấu hình cơ bản gồm:

```bash
docker compose --profile integrations up --build api frontend postgres redis email-ingest
```

Các service chính:

- `api`: FastAPI backend.
- `frontend`: Next.js dashboard.
- `postgres`: database chính.
- `redis`: cache/queue dự phòng.
- `email-ingest`: đọc mailbox IMAP.

Nếu cần kiểm thử pipeline Kafka/enrichment worker, có thể chạy thêm compose full:

```bash
docker compose -f docker-compose.yml -f docker-compose.full.yml --profile integrations up --build
```

Trong cấu hình full, Kafka và enrichment-worker được bật để xử lý security event theo mô hình streaming. Tuy nhiên, với mục tiêu local MVP, hệ thống vẫn có thể kiểm thử dashboard, auth OTP, runtime config, IMAP ingest, log ingest và assistant khi chỉ chạy compose cơ bản.

## 4.8 Kiểm thử và đánh giá hệ thống

Quá trình kiểm thử tập trung vào các nhóm chức năng chính:

1. Unit test backend cho auth, runtime config, detection logic và API service.
2. Build test frontend bằng `npm run build`.
3. Smoke test API và dashboard để kiểm tra kết nối frontend-backend.
4. Test email-ingest với runtime IMAP config và điều kiện OTP.
5. Test assistant bằng câu hỏi SOC, kiểm tra việc lấy log/email/alert gần nhất, gọi Threat Intel và gọi LLM.
6. Test Docker Compose để đảm bảo service khởi động đúng và networking local hoạt động.

Một kết quả smoke test đại diện cho thấy hệ thống trả dữ liệu logs, alerts, emails, mailbox emails, metrics và knowledge hits thành công. Luồng IMAP cũng đã được kiểm tra theo hướng: nếu chưa xác thực OTP cho IMAP User, email-ingest không đọc mailbox; sau khi xác thực OTP, API `/emails/mailbox` có thể trả email đã ingest tương ứng.

Các test case nghiệp vụ quan trọng gồm:

| Test case | Dữ liệu đầu vào | Kỳ vọng |
|---|---|---|
| Normal Login | User đăng nhập thành công từ IP nội bộ | LOW risk, không tạo alert nghiêm trọng |
| Brute Force | 100 failed SSH login từ một IP | HIGH risk, MITRE T1110, khuyến nghị MFA/chặn IP |
| Suspicious Login | Admin login từ quốc gia lạ sau failed attempts | HIGH risk, nghi valid account abuse |
| Malware Download | Tải `suspicious.exe` từ domain lạ | Malware activity, cảnh báo cao |
| SQL Injection | `/login.php?id=' OR 1=1 --` | Web attack, SQL Injection |
| Phishing Email | Email reset mật khẩu ngân hàng với URL lạ | HIGH risk, phishing/suspicious URL |
| Spam Email | Email trúng thưởng iPhone | Spam detected |
| Malware Attachment | Attachment `invoice.exe` | HIGH risk, malicious attachment |

Về đánh giá AI, hệ thống không huấn luyện mô hình ML mới. Kết quả phụ thuộc vào rule/heuristic, Threat Intel và LLM cloud được cấu hình. RAG lexical giúp giảm trả lời chung chung bằng cách bổ sung ngữ cảnh gần với sự kiện: MITRE technique, playbook xử lý, CVE hint, log/email/alert gần nhất.

## 4.9 Khó khăn trong quá trình thực hiện

Một số khó khăn chính trong quá trình triển khai gồm:

1. Tích hợp SMTP/IMAP Gmail: Gmail yêu cầu App Password, bật IMAP và xác thực hai bước. Nếu dùng mật khẩu Gmail thường, email-ingest trả lỗi `AUTHENTICATIONFAILED`.
2. Tách đúng vai trò SMTP và IMAP: SMTP dùng để gửi OTP/alert, còn IMAP dùng để đọc mailbox. Phiên bản cuối đã bỏ luồng "email cần theo dõi" riêng để tránh nhầm lẫn; mailbox cần đọc chính là IMAP User.
3. Cấu hình frontend-backend khi chạy local/VPS: nếu `NEXT_PUBLIC_API_BASE_URL` build sai thành `localhost` trong môi trường public, browser sẽ gọi nhầm máy client. Phiên bản local hiện đặt mặc định về `http://localhost:8000`.
4. Ràng buộc OTP cho IMAP: cần đảm bảo email-ingest không đọc mailbox khi người dùng chưa xác thực quyền sở hữu email.
5. Phụ thuộc LLM cloud: nếu API key/base URL/model sai, assistant sẽ lỗi. Do đó hệ thống cho phép cấu hình runtime trên UI và trả lỗi rõ ràng thay vì dùng fallback giả.
6. Giới hạn RAG lexical: BM25-lite nhẹ và dễ chạy local, nhưng không mạnh bằng vector search trong các truy vấn ngữ nghĩa phức tạp.

Những vấn đề này được xử lý bằng cách tách service, bổ sung runtime config, thêm OTP cho IMAP, cập nhật tài liệu chạy local và loại bỏ các thành phần không còn dùng như Qdrant.

## 4.10 Kết quả đạt được và định hướng mở rộng

Phiên bản hiện tại của AI_SOC đã hoàn thành các mục tiêu MVP chính:

- Có cơ chế đăng ký, đăng nhập và xác thực OTP qua SMTP.
- Có dashboard Next.js hiển thị log, email, alert, incident và assistant.
- Có backend FastAPI lưu dữ liệu vào PostgreSQL.
- Có collector-agent cho Windows/Ubuntu log.
- Có email-ingest đọc mailbox IMAP sau khi xác thực OTP.
- Có runtime settings để cấu hình SMTP, IMAP và Cloud LLM API trên giao diện.
- Có RAG lexical/BM25-lite kết hợp knowledge base nội bộ với log/email/alert gần nhất.
- Có gọi Threat Intel API và LLM cloud trong assistant/enrichment.
- Có Docker Compose để chạy local, kèm profile tích hợp email-ingest và compose full cho Kafka/enrichment-worker.

Tuy nhiên, hệ thống vẫn có một số hạn chế:

- Chưa dùng vector database, nên truy hồi ngữ nghĩa chưa sâu như RAG embedding.
- Chưa có mô hình ML local hoặc fine-tuned riêng cho log/email security.
- Kafka/enrichment-worker phù hợp kiểm thử full pipeline nhưng chưa được tối ưu như production SOC lớn.
- Chưa có cơ chế SOAR tự động phản ứng, do đã được loại khỏi phạm vi hiện tại.
- Kết quả AI phụ thuộc chất lượng LLM cloud và cấu hình API key/base URL/model.
- Dữ liệu kiểm thử chủ yếu là mô phỏng/smoke test, cần benchmark lớn hơn nếu muốn công bố định lượng học thuật.

Hướng phát triển tiếp theo gồm:

1. Bổ sung benchmark lớn từ CICIDS2017, UNSW-NB15, SpamAssassin, Enron hoặc PhishTank ở mức dữ liệu hợp pháp và đã ẩn danh.
2. Cải thiện RAG bằng hybrid retrieval: giữ BM25-lite cho keyword/IOC, sau đó có thể thêm vector search nếu cần mở rộng.
3. Bổ sung đánh giá định lượng: accuracy, precision, recall, F1-score, latency, throughput và hallucination rate.
4. Hoàn thiện correlation/incident timeline để hỗ trợ điều tra SOC tốt hơn.
5. Tăng khả năng quan sát hệ thống: metrics, tracing, health dashboard và log lỗi service.
6. Thêm policy bảo mật dữ liệu khi gửi log/email sang LLM cloud.

Kết luận chương 4: AI_SOC đã được triển khai thành một hệ thống SOC MVP chạy local, tích hợp log/email ingest, dashboard realtime, alert, Threat Intel, RAG lexical và LLM cloud. So với thiết kế ban đầu, phiên bản cuối đã lược bỏ Qdrant/vector embedding để giảm độ phức tạp vận hành, đồng thời tập trung vào luồng thực dụng: thu thập dữ liệu, chuẩn hóa, truy hồi ngữ cảnh nhẹ, gọi LLM và hiển thị cảnh báo. Hệ thống phù hợp cho mô hình nghiên cứu/prototype và có nền tảng rõ ràng để mở rộng thành giải pháp SOC tự động hóa sâu hơn trong các giai đoạn tiếp theo.
