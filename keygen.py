import os
from pathlib import Path

from secure_transfer_utils import generate_rsa_keypair

RECEIVER_PRIVATE_KEY_PATH = Path(os.getenv("RECEIVER_PRIVATE_KEY", "keys/receiver_private.pem"))
RECEIVER_PUBLIC_KEY_PATH = Path(os.getenv("RECEIVER_PUBLIC_KEY", "keys/receiver_public.pem"))

SENDER_PRIVATE_KEY_PATH = Path(os.getenv("SENDER_PRIVATE_KEY", "keys/sender_private.pem"))
SENDER_PUBLIC_KEY_PATH = Path(os.getenv("SENDER_PUBLIC_KEY", "keys/sender_public.pem"))


def main() -> None:
    # Receiver keys (giữ nguyên logic cũ)
    generate_rsa_keypair(RECEIVER_PRIVATE_KEY_PATH, RECEIVER_PUBLIC_KEY_PATH)
    print(f"[+] Đã tạo khóa riêng: {RECEIVER_PRIVATE_KEY_PATH}")
    print(f"[+] Đã tạo khóa công khai: {RECEIVER_PUBLIC_KEY_PATH}")

    # Sender keys (thêm theo yêu cầu Digital Signature)
    generate_rsa_keypair(SENDER_PRIVATE_KEY_PATH, SENDER_PUBLIC_KEY_PATH)
    print(f"[+] Đã tạo khóa riêng: {SENDER_PRIVATE_KEY_PATH}")
    print(f"[+] Đã tạo khóa công khai: {SENDER_PUBLIC_KEY_PATH}")

    print("[!] Chỉ chia sẻ public key cho bên còn lại. Không commit private key thật lên GitHub.")



if __name__ == "__main__":
    main()
