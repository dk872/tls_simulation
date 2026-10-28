import socket
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

        # Крок 2: Server Hello
        server_random = recv_msg(client_socket)
        public_key_bytes = recv_msg(client_socket)
        print("[2] Отримано Server Hello (server_random + public_key).")

        # Крок 4: обмін секретними рядками (Premaster Secret)
        premaster_secret = os.urandom(48)  # 48 байтів за стандартом TLS
        enc_premaster = rsa_encrypt(public_key_bytes, premaster_secret)
        send_msg(client_socket, enc_premaster)
        print("[4] Згенеровано та відправлено зашифрований Premaster Secret.")

        # Крок 5: генерація ключів сеансу
        session_key = generate_session_key(client_random, server_random, premaster_secret)
        print("[5] Згенеровано симетричний Session Key.")

        # Крок 6: готовність (Ready messages)
        # Шифруємо і відправляємо READY
        enc_client_ready = symmetric_encrypt(session_key, b"READY")
        send_msg(client_socket, enc_client_ready)

        # Отримуємо і розшифровуємо відповідь сервера
        enc_server_ready = recv_msg(client_socket)
        server_ready = symmetric_decrypt(session_key, enc_server_ready)
        if server_ready != b"READY":
            raise Exception("[-] Помилка підтвердження від сервера!")
        print("[6] Сервер підтвердив готовність. Рукостискання успішне!\n")

        # Крок 7: захищена передача даних (3D Mesh)
        print(f"[*] Читання 3D мешу з {filepath}...")
        with open(filepath, 'rb') as f:
            file_data = f.read()

        # 1. Відправляємо зашифровану назву файлу
        enc_filename = symmetric_encrypt(session_key, FILE_TO_SEND.encode('utf-8'))
        send_msg(client_socket, enc_filename)

        # 2. Відправляємо зашифрований вміст файлу
        enc_file_data = symmetric_encrypt(session_key, file_data)
        send_msg(client_socket, enc_file_data)

        print(f"[7] Файл {FILE_TO_SEND} успішно зашифровано та відправлено!")


if __name__ == "__main__":
    start_client()
