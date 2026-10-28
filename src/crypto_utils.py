import os
import hashlib
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keys():
    """
    Генерує пару RSA-ключів.
    Повертає приватний ключ (об'єкт) та публічний ключ у форматі байтів (PEM),
    щоб його можна було легко передати через сокети.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048 біт - стандарт для базової безпеки
    )

    public_key = private_key.public_key()

    # Серіалізуємо публічний ключ у послідовність байтів
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key_bytes


def generate_rsa_keys_and_cert():
    """Генерує RSA-ключі та самопідписаний сертифікат X.509 для сервера."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Створюємо параметри сертифіката (Хто видав і кому видано)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"KPI Secure Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
    ])

    # Збираємо сертифікат
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Сертифікат дійсний 1 рік
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    return private_key, cert_bytes


def rsa_encrypt(public_key_bytes: bytes, data: bytes) -> bytes:
    """
    Шифрує дані (premaster secret) за допомогою публічного ключа сервера.
    """
    # Відновлюємо об'єкт ключа з байтів
    public_key = serialization.load_pem_public_key(public_key_bytes)

    # Використовуємо OAEP padding
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """
    Розшифровує дані за допомогою приватного ключа сервера.
    """
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data


def generate_session_key(client_random: bytes, server_random: bytes, premaster_secret: bytes) -> bytes:
    """
    Генерує симетричний сеансовий ключ.
    У справжньому TLS використовується алгоритм PRF (Pseudo-Random Function),
    але для нашої імітації достатньо надійного SHA-256 хешування комбінації всіх трьох секретів.
    Повертає 32 байти (256 біт).
    """
    combined_data = client_random + server_random + premaster_secret
    session_key = hashlib.sha256(combined_data).digest()
    return session_key


def symmetric_encrypt(session_key: bytes, plaintext: bytes) -> bytes:
    """
    Шифрує дані симетричним ключем за допомогою AES-GCM.
    AES-GCM не лише шифрує, але й забезпечує цілісність (автентифікацію) повідомлення.
    """
    aesgcm = AESGCM(session_key)
    # Для AES-GCM потрібен унікальний вектор ініціалізації (nonce) на кожне повідомлення (12 байтів)
    nonce = os.urandom(12)

    # Шифруємо дані
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Прикріплюємо nonce на початок повідомлення, щоб одержувач зміг його розшифрувати.
    return nonce + ciphertext


def symmetric_decrypt(session_key: bytes, encrypted_payload: bytes) -> bytes:
    """
    Розшифровує дані, зашифровані AES-GCM.
    """
    aesgcm = AESGCM(session_key)

    # Відділяємо перші 12 байтів (nonce) від самого зашифрованого тексту
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]

    # Розшифровуємо (якщо дані були пошкоджені в дорозі, тут виникне помилка InvalidTag)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    return plaintext


if __name__ == "__main__":
    print("[*] Тестування криптографічних функцій...")

    # 1. Тест RSA
    priv_key, pub_key_bytes = generate_rsa_keys()
    premaster = os.urandom(48)  # premaster secret зазвичай має 48 байтів
    enc_premaster = rsa_encrypt(pub_key_bytes, premaster)
    dec_premaster = rsa_decrypt(priv_key, enc_premaster)
    assert premaster == dec_premaster, "Помилка шифрування RSA!"

    # 2. Тест сеансового ключа
    c_rand = os.urandom(32)
    s_rand = os.urandom(32)
    session_key = generate_session_key(c_rand, s_rand, dec_premaster)

    # 3. Тест AES-GCM
    test_msg = b"Hello, secure TLS world!"
    enc_msg = symmetric_encrypt(session_key, test_msg)
    dec_msg = symmetric_decrypt(session_key, enc_msg)
    assert test_msg == dec_msg, "Помилка шифрування AES!"

    print("[+] Усі криптографічні функції працюють коректно!")
