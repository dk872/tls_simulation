import socket
import threading
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import generate_rsa_keys, rsa_decrypt, generate_session_key, symmetric_encrypt, symmetric_decrypt

HOST = '127.0.0.1'
PORT = 65432
RECEIVED_DIR = os.path.join(BASE_DIR, 'received_data')


def send_msg(sock, data: bytes):
    """Відправляє повідомлення, додаючи на початок 4 байти з його довжиною."""
    # Конвертуємо довжину повідомлення у 4 байти
    length_prefix = len(data).to_bytes(4, byteorder='big')
    sock.sendall(length_prefix + data)


def recv_exact(sock, num_bytes: int) -> bytes | None:
    """Гарантовано зчитує вказану кількість байтів з сокета."""
    data = b''
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data


def recv_msg(sock) -> bytes | None:
    """Зчитує повідомлення, спочатку дізнаючись його довжину з перших 4 байтів."""
    length_prefix = recv_exact(sock, 4)
    if not length_prefix:
        return None
    msg_length = int.from_bytes(length_prefix, byteorder='big')
    return recv_exact(sock, msg_length)


def handle_client(conn, addr, private_key, public_key_bytes):
    """Обробляє підключення одного клієнта (TLS-рукостискання та прийом 3D-мешу)."""
    print(f"[+] Нове підключення: {addr}")

    try:
        # Крок 1: Client Hello
        client_random = recv_msg(conn)
        if not client_random:
            return
        print(f"[{addr}] 1. Отримано Client Hello (client_random).")

        # Крок 2: Server Hello
        server_random = os.urandom(32)
        send_msg(conn, server_random)
        send_msg(conn, public_key_bytes)
        print(f"[{addr}] 2. Відправлено Server Hello (server_random + public_key).")

        # Крок 4: обмін секретними рядками (Premaster Secret)
        enc_premaster = recv_msg(conn)
        premaster_secret = rsa_decrypt(private_key, enc_premaster)
        print(f"[{addr}] 4. Отримано та розшифровано Premaster Secret.")

        # Крок 5: генерація ключів сеансу
        session_key = generate_session_key(client_random, server_random, premaster_secret)
        print(f"[{addr}] 5. Згенеровано симетричний Session Key.")

        # Крок 6: готовність (Ready messages)
        # Клієнт надсилає зашифроване повідомлення "READY"
        enc_client_ready = recv_msg(conn)
        client_ready = symmetric_decrypt(session_key, enc_client_ready)
        if client_ready != b"READY":
            raise Exception("Помилка перевірки готовності клієнта!")
        print(f"[{addr}] 6. Клієнт підтвердив готовність (зашифрований зв'язок працює).")

        # Сервер відповідає своїм "READY"
        enc_server_ready = symmetric_encrypt(session_key, b"READY")
        send_msg(conn, enc_server_ready)
        print(f"[{addr}] 6. Сервер підтвердив готовність. Рукостискання завершено!\n")

        # Крок 7: захищена передача даних (All-to-One 3D Mesh)
        print(f"[{addr}] Очікування захищених даних (3D мешу)...")

        # Спочатку отримуємо назву файлу
        enc_filename = recv_msg(conn)
        if enc_filename:
            filename = symmetric_decrypt(session_key, enc_filename).decode('utf-8')

            # Потім отримуємо вміст файлу
            enc_file_data = recv_msg(conn)
            file_data = symmetric_decrypt(session_key, enc_file_data)

            # Щоб файли від різних клієнтів не перезаписували один одного, додаємо порт клієнта до назви
            safe_filename = f"{addr[1]}_{filename}"
            filepath = os.path.join(RECEIVED_DIR, safe_filename)

            with open(filepath, 'wb') as f:
                f.write(file_data)

            print(f"[{addr}] 7. Успішно отримано та розшифровано 3D меш!")
            print(f"[{addr}] Файл збережено як: {filepath}\n")

    except Exception as e:
        print(f"[-] Помилка під час обслуговування клієнта {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] З'єднання з {addr} закрито.")


def start_server():
    # Створюємо папку для збереження отриманих файлів
    os.makedirs(RECEIVED_DIR, exist_ok=True)

    # Генерація RSA ключів відбувається ОДИН раз при старті сервера
    print("[*] Генерація серверних RSA ключів...")
    private_key, public_key_bytes = generate_rsa_keys()
    print("[*] Ключі успішно згенеровано.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Дозволяємо повторно використовувати адресу одразу після зупинки сервера (запобігає Address already in use)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[*] Сервер запущено та прослуховує {HOST}:{PORT}")
        print("[*] Очікування клієнтів (режим All-to-One)...\n")

        while True:
            conn, addr = server_socket.accept()
            # Для кожного нового клієнта створюється окремий потік.
            # Це дозволяє декільком клієнтам одночасно проходити рукостискання і відправляти 3D меші.
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, private_key, public_key_bytes)
            )
            client_thread.start()


if __name__ == "__main__":
    start_server()
