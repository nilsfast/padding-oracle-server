from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import socket

KEY = b"AAAAAAAAAAAAAAAA"
IV = b"IVIVIVIVIVIVIVIV"


assert len(KEY) == len(IV) == 16

print("Key:", base64.b64encode(KEY).decode())
print("IV:", base64.b64encode(IV).decode())

AES_CIPHER = AES.new(KEY, AES.MODE_CBC, IV)


def recv_exact(socket, n):
    data = b""
    while len(data) < n:
        chunk = socket.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before receiving expected data")
        data += chunk
    return data


def pad_and_encrypt(input_text: str) -> bytes:
    # Decode the base64 input text
    decoded_input = base64.b64decode(input_text)

    # Pad the input text according to PKCS#7
    padded_input = pad(decoded_input, AES.block_size)

    print("Padded input:")
    print("\tBytes:", padded_input)
    print("\tBase64:", base64.b64encode(padded_input))

    # Create AES cipher in CBC mode

    # Encrypt the padded input
    ciphertext = AES_CIPHER.encrypt(padded_input)

    return ciphertext


# for performace reasons, create the decryptor only once
DECRYPT_AES = AES.new(KEY, AES.MODE_CBC, IV)


def padding_oracle(ciphertext: bytes) -> bool:
    try:
        # Decrypt the ciphertext and check padding in one step
        decryptor = AES.new(KEY, AES.MODE_CBC, IV)
        unpad(decryptor.decrypt(ciphertext), AES.block_size)
        return True # Padding is correct
    except (ValueError, KeyError):
        return False # Padding is incorrect



def handle_client(client_socket, injected_ciphertext=None):
    try:
        # Step 1: Receive Initial Data (if any)
        print("Waiting for key_id (2 bytes)")

        key_id = client_socket.recv(2)
        if len(key_id) != 2:
            print("Invalid key_id received.")
            return
        print(f"Received key_id: {key_id.hex()}")

        if injected_ciphertext:
            ciphertext = injected_ciphertext
        else:
            # Step 2: Receive Initial Ciphertext (16 bytes)
            print("Waiting for ciphertext (16 bytes)")
            ciphertext = client_socket.recv(16)
            if len(ciphertext) != 16:
                print("Invalid Ciphertext received:", ciphertext.hex())
                return
            print(f"Received ciphertext: {ciphertext.hex()}")

        while True:
            # Step 3: Receive Length Field (2 bytes)
            length_field = client_socket.recv(2)
            if len(length_field) != 2:
                print("Invalid Length Field received.")
                return

            l = int.from_bytes(length_field, byteorder="little")
            print("recieved length:", length_field, l)

            if l == 0:
                print("Connection termination signal received.")
                break

            # Step 4: Receive Q-Blocks (16 * l bytes)
            q_blocks = recv_exact(client_socket, 16 * l)
            if len(q_blocks) != 16 * l:
                print("Invalid Q-Blocks received.")
                return

            # Process all Q-Blocks in a single loop
            response = bytearray(
                (
                    0x01
                    if padding_oracle(q_blocks[i * 16 : (i + 1) * 16] + ciphertext)
                    else 0x00
                )
                for i in range(l)
            )

            # Step 5: Send Response (l bytes)
            client_socket.send(response)
            print(f"Sent {l} responses.")
    finally:
        client_socket.close()


def start_server(plaintext, host="localhost", port=12345):
    ciphertext = pad_and_encrypt(base64.b64encode(plaintext).decode())
    print("Ciphertext:")
    print("\tHex:", ciphertext.hex())
    print("\tBase64:", base64.b64encode(ciphertext).decode())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            s.bind((host, port))
            print(f"\nServer listening on {host}:{port}")
            s.listen()
            while True:
                conn, addr = s.accept()
                with conn:
                    print()
                    print(f"New connection: {addr}")
                    handle_client(conn)
                    print("Connection terminated.")
        except KeyboardInterrupt:
            print("Server shutting down.")
            s.close()
        finally:
            s.close()


if __name__ == "__main__":
    PLAINTEXT = b"Ich bin ein kleiner plaintext"
    start_server(PLAINTEXT, "localhost", 12345)
