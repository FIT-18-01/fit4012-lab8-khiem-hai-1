# Lab 8 - Báo cáo 1 trang

## 1. Mục tiêu

Xây dựng chương trình truyền dữ liệu an toàn qua socket bằng cách kết hợp DES-CBC, SHA-256 và RSA-OAEP.

## 2. Luồng xử lý Sender

1. Đọc plaintext từ biến môi trường `MESSAGE`, file `INPUT_FILE` hoặc bàn phím.
2. Tính SHA-256 của plaintext gốc.
3. Sinh ngẫu nhiên DES key 8 byte và IV 8 byte.
4. Mã hóa plaintext bằng DES-CBC, đặt IV ở đầu ciphertext.
5. Mã hóa DES key bằng RSA public key của Receiver.
6. Gửi packet qua socket theo định dạng Lab 8.

## 3. Luồng xử lý Receiver

1. Nhận packet qua socket.
2. Tách encrypted DES key, ciphertext và SHA-256 hash.
3. Dùng RSA private key để giải mã DES key.
4. Dùng DES key để giải mã ciphertext.
5. Tính lại SHA-256 của plaintext nhận được.
6. So sánh hash để kết luận dữ liệu nguyên vẹn hay đã bị thay đổi.

## 4. Kết quả minh chứng

- Ảnh chụp màn hình Sender: Chạy local và lưu log trong `logs/sender_success.log`
- Ảnh chụp màn hình Receiver: Chạy local và lưu log trong `logs/receiver_success.log`
- File log Sender: `logs/sender_success.log`
- File log Receiver: `logs/receiver_success.log`

## 5. Nhận xét

Cơ chế RSA-OAEP giúp bảo vệ khóa DES khi truyền qua mạng. SHA-256 giúp Receiver phát hiện thay đổi trên dữ liệu sau khi giải mã. Tuy nhiên, DES không còn phù hợp cho hệ thống thật; hướng nâng cấp nên là AES-GCM hoặc AES-CBC kết hợp cơ chế xác thực mạnh hơn.
