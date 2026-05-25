import hashlib
import os
import socket
import struct
from pathlib import Path
from typing import Tuple


from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

DES_BLOCK_SIZE = 8
DES_KEY_SIZE = 8
DES_IV_SIZE = 8
RSA_KEY_SIZE = 2048
LENGTH_HEADER_SIZE = 4
SHA256_DIGEST_SIZE = 32


def sha256_digest(data: bytes) -> bytes:
    """Return SHA-256 digest bytes for the original plaintext."""
    return hashlib.sha256(data).digest()


def generate_des_key_iv() -> Tuple[bytes, bytes]:
    """Generate a random DES key and CBC IV, each 8 bytes."""
    return os.urandom(DES_KEY_SIZE), os.urandom(DES_IV_SIZE)


def validate_des_key_iv(des_key: bytes, iv: bytes) -> None:
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key phải dài đúng 8 byte.")
    if len(iv) != DES_IV_SIZE:
        raise ValueError("IV của DES-CBC phải dài đúng 8 byte.")


def encrypt_des_cbc(
    plaintext: bytes,
    des_key: bytes | None = None,
    iv: bytes | None = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with DES-CBC and PKCS#7 padding.

    Returns: des_key, iv, ciphertext_with_iv.
    The transmitted ciphertext includes IV at the beginning as required by Lab 8.
    """
    if des_key is None or iv is None:
        des_key, iv = generate_des_key_iv()

    validate_des_key_iv(des_key, iv)
    cipher_des = DES.new(des_key, DES.MODE_CBC, iv)
    encrypted_body = cipher_des.encrypt(pad(plaintext, DES_BLOCK_SIZE))
    return des_key, iv, iv + encrypted_body


def decrypt_des_cbc(des_key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """Decrypt ciphertext whose first 8 bytes are the DES-CBC IV."""
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key phải dài đúng 8 byte.")
    if len(ciphertext_with_iv) <= DES_IV_SIZE:
        raise ValueError("Ciphertext phải gồm IV và phần bản mã.")

    iv = ciphertext_with_iv[:DES_IV_SIZE]
    encrypted_body = ciphertext_with_iv[DES_IV_SIZE:]

    if len(encrypted_body) % DES_BLOCK_SIZE != 0:
        raise ValueError("Phần bản mã DES-CBC phải có độ dài là bội số của 8 byte.")

    cipher_des = DES.new(des_key, DES.MODE_CBC, iv)
    return unpad(cipher_des.decrypt(encrypted_body), DES_BLOCK_SIZE)


def generate_rsa_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Generate a 2048-bit RSA key pair and write PEM files."""
    private_path = Path(private_path)
    public_path = Path(public_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    key = RSA.generate(RSA_KEY_SIZE)
    private_path.write_bytes(key.export_key())
    public_path.write_bytes(key.publickey().export_key())


def load_public_key(path: str | Path):
    """Load an RSA public key from a PEM file."""
    return RSA.import_key(Path(path).read_bytes())


def load_private_key(path: str | Path):
    """Load an RSA private key from a PEM file."""
    return RSA.import_key(Path(path).read_bytes())


def sign_hash(hash_obj, private_key) -> bytes:
    """Sign a pre-computed hash object using RSA PKCS#1 v1.5."""
    from Crypto.Signature import pkcs1_15

    return pkcs1_15.new(private_key).sign(hash_obj)


def verify_signature(hash_obj, signature: bytes, public_key) -> bool:
    """Verify an RSA PKCS#1 v1.5 signature. Return True/False."""
    from Crypto.Signature import pkcs1_15

    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False




def encrypt_des_key_rsa(des_key: bytes, receiver_public_key) -> bytes:
    """Encrypt the DES session key with receiver's RSA public key using OAEP."""
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key phải dài đúng 8 byte trước khi mã hóa RSA.")
    rsa_cipher = PKCS1_OAEP.new(receiver_public_key)
    return rsa_cipher.encrypt(des_key)


def decrypt_des_key_rsa(encrypted_des_key: bytes, receiver_private_key) -> bytes:
    """Decrypt the DES session key with receiver's RSA private key using OAEP."""
    rsa_cipher = PKCS1_OAEP.new(receiver_private_key)
    des_key = rsa_cipher.decrypt(encrypted_des_key)
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key sau khi giải mã RSA không đúng 8 byte.")
    return des_key


def pack_length(data: bytes) -> bytes:
    """Pack byte length as 4-byte unsigned integer in network byte order."""
    if len(data) <= 0:
        raise ValueError("Không được đóng gói dữ liệu rỗng.")
    return struct.pack("!I", len(data))


def parse_length_header(header: bytes) -> int:
    """Parse a 4-byte network-order length header."""
    if len(header) != LENGTH_HEADER_SIZE:
        raise ValueError("Length header phải dài đúng 4 byte.")
    length = struct.unpack("!I", header)[0]
    if length <= 0:
        raise ValueError("Length header phải lớn hơn 0.")
    return length


def build_secure_packet(
    encrypted_des_key: bytes,
    ciphertext_with_iv: bytes,
    plaintext_hash: bytes,
    signature: bytes | None = None,
) -> bytes:

    """
    Build Lab 8 packet (nâng cấp Digital Signature):
    [len_key:4]
    [encrypted_des_key]
    [len_cipher:4]
    [ciphertext_with_iv]
    [sha256_hash:32]
    [len_signature:4]
    [signature]
    """
    if len(plaintext_hash) != SHA256_DIGEST_SIZE:
        raise ValueError("SHA-256 hash phải dài đúng 32 byte.")
    if signature is None:
        # Backward compatibility: nếu gọi theo format cũ (không chữ ký)
        # thì tạo packet cũ: [len_key][encrypted_des_key][len_cipher][ciphertext_with_iv][sha256_hash]
        return (
            pack_length(encrypted_des_key)
            + encrypted_des_key
            + pack_length(ciphertext_with_iv)
            + ciphertext_with_iv
            + plaintext_hash
        )

    if len(signature) <= 0:
        raise ValueError("Chữ ký không hợp lệ (rỗng).")

    return (

        pack_length(encrypted_des_key)
        + encrypted_des_key
        + pack_length(ciphertext_with_iv)
        + ciphertext_with_iv
        + plaintext_hash
        + pack_length(signature)
        + signature
    )



def parse_secure_packet(packet: bytes) -> Tuple[bytes, bytes, bytes]:
    """Parse a complete Lab 8 packet into encrypted DES key, ciphertext, and hash.

    Parse theo format cũ (không chữ ký). Nếu còn dư dữ liệu thì raise ValueError.
    """



    cursor = 0

    enc_key_len = parse_length_header(packet[cursor:cursor + LENGTH_HEADER_SIZE])
    cursor += LENGTH_HEADER_SIZE
    encrypted_des_key = packet[cursor:cursor + enc_key_len]
    if len(encrypted_des_key) != enc_key_len:
        raise ValueError("Packet thiếu encrypted DES key.")
    cursor += enc_key_len

    cipher_len = parse_length_header(packet[cursor:cursor + LENGTH_HEADER_SIZE])
    cursor += LENGTH_HEADER_SIZE
    ciphertext_with_iv = packet[cursor:cursor + cipher_len]
    if len(ciphertext_with_iv) != cipher_len:
        raise ValueError("Packet thiếu ciphertext.")
    cursor += cipher_len

    plaintext_hash = packet[cursor:cursor + SHA256_DIGEST_SIZE]
    if len(plaintext_hash) != SHA256_DIGEST_SIZE:
        raise ValueError("Packet thiếu SHA-256 hash.")
    cursor += SHA256_DIGEST_SIZE

    # Format cũ kết thúc ngay tại SHA256 hash.
    # Nếu còn dư bytes => packet không hợp lệ.
    if cursor != len(packet):
        raise ValueError("Packet có dữ liệu thừa không đúng định dạng.")

    return encrypted_des_key, ciphertext_with_iv, plaintext_hash






def build_sender_payload(
    plaintext: bytes,
    receiver_public_key,
    sender_private_key_path: str | Path | None = "keys/sender_private.pem",
) -> Tuple[bytes, bytes, bytes, bytes]:


    """
    Build the bytes that Sender sends through socket.

    Returns: packet, des_key, ciphertext_with_iv, plaintext_hash.
    Packet đã bao gồm digital signature.
    """
    plaintext_hash = sha256_digest(plaintext)
    des_key, _iv, ciphertext_with_iv = encrypt_des_cbc(plaintext)
    encrypted_des_key = encrypt_des_key_rsa(des_key, receiver_public_key)

    if sender_private_key_path is None:
        # Dùng token signature không cần (chạy tests cũ không có file key)
        # => tạo chữ ký giả không hợp lệ sẽ làm integrity_ok=false phía receiver.
        # Tuy nhiên tests hiện tại chỉ dùng open_receiver_payload để kiểm tra integrity.
        # Vì receiver.verify sẽ fail nếu chữ ký không khớp, ta sẽ đảm bảo tests tạo key đủ.
        raise ValueError("sender_private_key_path không được None")

    # Nếu path không tồn tại (tests), fallback: tạo chữ ký không cần file bằng cách sinh key tạm.
    # Để giữ logic test_lab8_crypto, ta sinh key từ receiver public key không được (không đủ private).
    # Do đó, bộ test kỳ vọng build_sender_payload vẫn chạy => phải có sender private key sẵn trong file hoặc được truyền.
    sender_private_key = load_private_key(sender_private_key_path)

    # Ký lên hash của plaintext bằng RSA private key (digital signature)
    from Crypto.Hash import SHA256 as CryptoSHA256

    hash_obj = CryptoSHA256.new(plaintext)
    signature = sign_hash(hash_obj, sender_private_key)


    packet = build_secure_packet(
        encrypted_des_key,
        ciphertext_with_iv,
        plaintext_hash,
        signature,
    )
    return packet, des_key, ciphertext_with_iv, plaintext_hash



def open_receiver_payload(
    packet: bytes,
    receiver_private_key,
    sender_public_key_path: str | Path = "keys/sender_public.pem",
) -> Tuple[bytes, bool]:

    """
    Parse, decrypt, và verify received Lab 8 packet.

    Returns: plaintext, integrity_ok.
    integrity_ok = SHA-256 match AND chữ ký số hợp lệ.
    """
    # Không dùng parse_secure_packet(packet) vì hàm này đang chỉ parse format cũ (không signature)
    # và sẽ reject packet nâng cấp. Vì vậy parse trực tiếp ở đây để lấy signature nếu có.

    cursor = 0
    enc_key_len = parse_length_header(packet[cursor:cursor + LENGTH_HEADER_SIZE])
    cursor += LENGTH_HEADER_SIZE
    encrypted_des_key = packet[cursor:cursor + enc_key_len]
    cursor += enc_key_len

    cipher_len = parse_length_header(packet[cursor:cursor + LENGTH_HEADER_SIZE])
    cursor += LENGTH_HEADER_SIZE
    ciphertext_with_iv = packet[cursor:cursor + cipher_len]
    cursor += cipher_len

    received_hash = packet[cursor:cursor + SHA256_DIGEST_SIZE]
    cursor += SHA256_DIGEST_SIZE

    signature = b""


    # Nếu còn dư: packet có thể có signature
    if len(packet) - cursor >= LENGTH_HEADER_SIZE:
        sig_len = parse_length_header(packet[cursor:cursor + LENGTH_HEADER_SIZE])
        cursor += LENGTH_HEADER_SIZE
        signature = packet[cursor:cursor + sig_len]


    des_key = decrypt_des_key_rsa(encrypted_des_key, receiver_private_key)

    plaintext = decrypt_des_cbc(des_key, ciphertext_with_iv)

    calculated_hash = sha256_digest(plaintext)
    sha_ok = calculated_hash == received_hash

    sender_public_key = load_public_key(sender_public_key_path)

    from Crypto.Hash import SHA256 as CryptoSHA256

    hash_obj = CryptoSHA256.new(plaintext)
    sig_ok = verify_signature(hash_obj, signature, sender_public_key)


    return plaintext, (sha_ok and sig_ok)



def recv_exact(conn, n: int) -> bytes:
    """Receive exactly n bytes from a TCP connection."""
    if n <= 0:
        raise ValueError("Số byte cần nhận phải lớn hơn 0.")

    chunks = []
    received = 0
    while received < n:
        chunk = conn.recv(n - received)
        if not chunk:
            raise ConnectionError("Kết nối bị đóng trước khi nhận đủ dữ liệu.")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def recv_secure_packet(conn) -> bytes:
    """Receive one Lab 8 secure packet from a connected socket.

    Format (nâng cấp):
    [len_key:4][encrypted_des_key][len_cipher:4][ciphertext_with_iv][sha256_hash:32][len_signature:4][signature]

    Đồng thời hỗ trợ format cũ (không signature) để tương thích test.
    """

    enc_key_len_header = recv_exact(conn, LENGTH_HEADER_SIZE)
    enc_key_len = parse_length_header(enc_key_len_header)
    encrypted_des_key = recv_exact(conn, enc_key_len)

    cipher_len_header = recv_exact(conn, LENGTH_HEADER_SIZE)
    cipher_len = parse_length_header(cipher_len_header)
    ciphertext_with_iv = recv_exact(conn, cipher_len)

    plaintext_hash = recv_exact(conn, SHA256_DIGEST_SIZE)

    # Nếu phía sender đóng kết nối ngay sau sha256_hash => packet format cũ
    # Không có signature.
    try:
        sig_len_header = conn.recv(LENGTH_HEADER_SIZE, socket.MSG_PEEK)
        if len(sig_len_header) < LENGTH_HEADER_SIZE:
            return (
                enc_key_len_header
                + encrypted_des_key
                + cipher_len_header
                + ciphertext_with_iv
                + plaintext_hash
            )
    except Exception:
        return (
            enc_key_len_header
            + encrypted_des_key
            + cipher_len_header
            + ciphertext_with_iv
            + plaintext_hash
        )

    sig_len_header = recv_exact(conn, LENGTH_HEADER_SIZE)
    sig_len = parse_length_header(sig_len_header)
    signature = recv_exact(conn, sig_len)

    return (
        enc_key_len_header
        + encrypted_des_key
        + cipher_len_header
        + ciphertext_with_iv
        + plaintext_hash
        + sig_len_header
        + signature
    )


