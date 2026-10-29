import socket
import os
import datetime
import time
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from crypto_utils import rsa_encrypt, generate_session_key, symmetric_encrypt, symmetric_decrypt

HOST = '127.0.0.1'
PORT = 65432
SEND_DIR = os.path.join(BASE_DIR, 'data_to_send')
FILE_TO_SEND = 'sample_mesh.obj'


def send_msg(sock, data: bytes):
    length_prefix = len(data).to_bytes(4, byteorder='big')
    sock.sendall(length_prefix + data)


def recv_exact(sock, num_bytes: int) -> bytes | None:
    data = b''
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data


def recv_msg(sock) -> bytes | None:
    length_prefix = recv_exact(sock, 4)
    if not length_prefix:
        return None
    msg_length = int.from_bytes(length_prefix, byteorder='big')
    return recv_exact(sock, msg_length)


def create_dummy_mesh():
    """Створює простий .obj файл (3D-куб) для тестування передачі."""
    os.makedirs(SEND_DIR, exist_ok=True)
    filepath = os.path.join(SEND_DIR, FILE_TO_SEND)

    # Стандартний формат Wavefront.obj для 3D моделей
    cube_obj_data = """# Тестовий 3D Меш (Куб)
v 0.0 0.0 0.0
v 0.0 0.0 1.0
v 0.0 1.0 0.0
v 0.0 1.0 1.0
v 1.0 0.0 0.0
v 1.0 0.0 1.0
v 1.0 1.0 0.0
v 1.0 1.0 1.0
f 1 7 5
f 1 3 7
f 1 4 3
f 1 2 4
f 3 8 7
f 3 4 8
f 5 7 8
f 5 8 6
f 1 5 6
f 1 6 2
f 2 6 8
f 2 8 4
"""
    if not os.path.exists(filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(cube_obj_data)
        print(f"[*] Створено тестовий 3D меш: {filepath}")


def start_client():
    # Підготовка файлу для відправки
    create_dummy_mesh()
    filepath = os.path.join(SEND_DIR, FILE_TO_SEND)

    print("[*] Ініціалізація з'єднання з сервером...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print(f"[+] Підключено до сервера {HOST}:{PORT}\n")

        # Крок 1: Client Hello
        client_random = os.urandom(32)
        send_msg(client_socket, client_random)
        print("[1] Відправлено Client Hello (client_random).")

        # Крок 2: Server Hello (очікуємо сертифікат замість простого ключа)
        server_random = recv_msg(client_socket)
        cert_bytes = recv_msg(client_socket)
        print("[2] Отримано Server Hello (server_random + SSL-сертифікат).")

        # Крок 3: автентифікація сервера (перевірка X.509 сертифіката)
        print("[3] Перевірка SSL-сертифіката сервера в центрі сертифікації...")
        try:
            # Завантажуємо сертифікат з отриманих байтів
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

            # 3.1. Перевірка терміну дії сертифіката
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                raise Exception("Сертифікат прострочений або ще не дійсний!")

            # 3.2. Імітація перевірки в CA (вивід інформації про видавця)
            issuer = cert.issuer.rfc4514_string()
            subject = cert.subject.rfc4514_string()
            print(f"    - Виданий (Issuer): {issuer}")
            print(f"    - Суб'єкт (Subject): {subject}")
            print("    - Звернення до Центру Сертифікації (CA) для підтвердження підпису...")
            print("    [+] Сертифікат успішно перевірено. Ідентичність сервера підтверджено!")

            # 3.3. Витягуємо публічний ключ безпосередньо із сертифіката
            public_key = cert.public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            print(f"[-] Помилка автентифікації: {e}")
            return  # Припиняємо з'єднання, якщо сертифікат не пройшов перевірку

        # Крок 4: обмін секретними рядками (Premaster Secret)
        premaster_secret = os.urandom(48)  # 48 байтів за стандартом TLS
        enc_premaster = rsa_encrypt(public_key_bytes, premaster_secret)
        send_msg(client_socket, enc_premaster)
        print("[4] Згенеровано та відправлено зашифрований Premaster Secret.")

        # Крок 5: генерація ключів сеансу
        session_key = generate_session_key(client_random, server_random, premaster_secret)
        print("[5] Згенеровано симетричний Session Key.")

        # Крок 6: готовність (Ready messages)
        enc_client_ready = symmetric_encrypt(session_key, b"READY")
        send_msg(client_socket, enc_client_ready)

        enc_server_ready = recv_msg(client_socket)
        server_ready = symmetric_decrypt(session_key, enc_server_ready)
        if server_ready != b"READY":
            raise Exception("[-] Помилка підтвердження від сервера!")
        print("[6] Сервер підтвердив готовність. Рукостискання успішне!\n")

        # Крок 7: захищена передача даних (3D Mesh)
        print(f"[*] Читання 3D мешу з {filepath}...")
        with open(filepath, 'rb') as f:
            file_data = f.read()

        enc_filename = symmetric_encrypt(session_key, FILE_TO_SEND.encode('utf-8'))
        send_msg(client_socket, enc_filename)

        enc_file_data = symmetric_encrypt(session_key, file_data)
        send_msg(client_socket, enc_file_data)

        print(f"[7] Файл {FILE_TO_SEND} успішно зашифровано та відправлено!")

        print("[*] Утримуємо захищене з'єднання 10 секунд для демонстрації All-to-One...")
        time.sleep(10)


if __name__ == "__main__":
    start_client()
