import hashlib
import os
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


def build_secure_packet(encrypted_des_key: bytes, ciphertext_with_iv: bytes, plaintext_hash: bytes) -> bytes:
    """
    Build Lab 8 packet:
    [len_key][encrypted_des_key][len_cipher][ciphertext_with_iv][sha256_hash]
    """
    if len(plaintext_hash) != SHA256_DIGEST_SIZE:
        raise ValueError("SHA-256 hash phải dài đúng 32 byte.")
    return (
        pack_length(encrypted_des_key)
        + encrypted_des_key
        + pack_length(ciphertext_with_iv)
        + ciphertext_with_iv
        + plaintext_hash
    )


def parse_secure_packet(packet: bytes) -> Tuple[bytes, bytes, bytes]:
    """Parse a complete Lab 8 packet into encrypted DES key, ciphertext, and hash."""
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

    if cursor != len(packet):
        raise ValueError("Packet có dữ liệu thừa không đúng định dạng.")

    return encrypted_des_key, ciphertext_with_iv, plaintext_hash


def build_sender_payload(plaintext: bytes, receiver_public_key) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Build the bytes that Sender sends through socket.

    Returns: packet, des_key, ciphertext_with_iv, plaintext_hash.
    """
    plaintext_hash = sha256_digest(plaintext)
    des_key, _iv, ciphertext_with_iv = encrypt_des_cbc(plaintext)
    encrypted_des_key = encrypt_des_key_rsa(des_key, receiver_public_key)
    packet = build_secure_packet(encrypted_des_key, ciphertext_with_iv, plaintext_hash)
    return packet, des_key, ciphertext_with_iv, plaintext_hash


def open_receiver_payload(packet: bytes, receiver_private_key) -> Tuple[bytes, bool]:
    """
    Parse, decrypt, and verify received Lab 8 packet.

    Returns: plaintext, integrity_ok.
    """
    encrypted_des_key, ciphertext_with_iv, received_hash = parse_secure_packet(packet)
    des_key = decrypt_des_key_rsa(encrypted_des_key, receiver_private_key)
    plaintext = decrypt_des_cbc(des_key, ciphertext_with_iv)
    calculated_hash = sha256_digest(plaintext)
    return plaintext, calculated_hash == received_hash


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
    """
    Receive one Lab 8 secure packet from a connected socket.

    Format:
    [len_key:4][encrypted_des_key][len_cipher:4][ciphertext_with_iv][sha256_hash:32]
    """
    enc_key_len_header = recv_exact(conn, LENGTH_HEADER_SIZE)
    enc_key_len = parse_length_header(enc_key_len_header)
    encrypted_des_key = recv_exact(conn, enc_key_len)

    cipher_len_header = recv_exact(conn, LENGTH_HEADER_SIZE)
    cipher_len = parse_length_header(cipher_len_header)
    ciphertext_with_iv = recv_exact(conn, cipher_len)

    plaintext_hash = recv_exact(conn, SHA256_DIGEST_SIZE)
    return enc_key_len_header + encrypted_des_key + cipher_len_header + ciphertext_with_iv + plaintext_hash
