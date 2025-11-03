import socket
import struct
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
import json
import os
from datetime import datetime


class SecureLogServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.load_keys()


        self.storage_dir = "secure_logs"
        os.makedirs(self.storage_dir, exist_ok=True)

    def load_keys(self):

        try:
            with open("server_private_key.pem", "rb") as f:
                self.server_private_key = RSA.import_key(f.read())
            print("Server private key loaded")

            with open("client_public_key.pem", "rb") as f:
                self.client_public_key = RSA.import_key(f.read())
            print("Client public key loaded")

        except FileNotFoundError as e:
            print(f"Key file not found: {e}")
            raise

    def receive_exact_data(self, sock, length):

        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection lost while receiving data")
            data += chunk
        return data

    def receive_message(self, sock):


        length_bytes = self.receive_exact_data(sock, 4)
        length = struct.unpack(">I", length_bytes)[0]


        return self.receive_exact_data(sock, length)

    def decrypt_aes_key(self, encrypted_aes_key):
        """Decrypt AES key using server's private RSA key"""
        cipher_rsa = PKCS1_OAEP.new(self.server_private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        return aes_key

    def decrypt_logs(self, aes_key, encrypted_logs, tag, nonce):
        """Decrypt logs using AES-GCM"""
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_logs = cipher.decrypt_and_verify(encrypted_logs, tag)
        return decrypted_logs

    def verify_signature(self, logs_data, signature):
        """Verify digital signature using client's public key"""
        hash_obj = SHA512.new(logs_data)
        verifier = PKCS1_v1_5.new(self.client_public_key)

        try:
            verifier.verify(hash_obj, signature)
            print("✓ Signature verification SUCCESSFUL")
            return True
        except (ValueError, TypeError):
            print("✗ Signature verification FAILED")
            return False

    def store_logs_securely(self, logs_data, client_ip, verification_status):
        """Store logs securely with metadata"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logs_{timestamp}_{client_ip.replace('.', '_')}.enc"
        filepath = os.path.join(self.storage_dir, filename)


        metadata = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": client_ip,
            "log_size": len(logs_data),
            "signature_verified": verification_status,
            "storage_format": "encrypted"
        }


        try:

            with open(filepath, "wb") as f:

                metadata_json = json.dumps(metadata).encode()
                f.write(len(metadata_json).to_bytes(4, 'big'))
                f.write(metadata_json)
                f.write(logs_data)


            if verification_status:
                decrypted_dir = os.path.join(self.storage_dir, "decrypted")
                os.makedirs(decrypted_dir, exist_ok=True)

                decrypted_file = os.path.join(decrypted_dir, f"decrypted_{timestamp}.log")
                with open(decrypted_file, "wb") as f:
                    f.write(logs_data)

            print(f"✓ Logs stored securely in: {filepath}")
            return True

        except Exception as e:
            print(f"✗ Error storing logs: {e}")
            return False

    def handle_client(self, sock, client_addr):
        """Handle a single client connection"""
        print(f"\n=== New connection from {client_addr[0]}:{client_addr[1]} ===")

        try:

            encrypted_aes_key = self.receive_message(sock)
            print("✓ Encrypted AES key received")

            encrypted_logs = self.receive_message(sock)
            print("✓ Encrypted logs received")

            tag = self.receive_message(sock)
            print("✓ Authentication tag received")

            nonce = self.receive_message(sock)
            print("✓ Nonce received")

            signature = self.receive_message(sock)
            print("✓ Digital signature received")


            aes_key = self.decrypt_aes_key(encrypted_aes_key)
            print("✓ AES key decrypted")


            decrypted_logs = self.decrypt_logs(aes_key, encrypted_logs, tag, nonce)
            print("✓ Logs decrypted successfully")
            print(f"✓ Decrypted log size: {len(decrypted_logs)} bytes")


            signature_valid = self.verify_signature(decrypted_logs, signature)


            storage_success = self.store_logs_securely(
                decrypted_logs,
                client_addr[0],
                signature_valid
            )


            ack_message = json.dumps({
                "status": "success" if signature_valid and storage_success else "error",
                "signature_valid": signature_valid,
                "storage_success": storage_success,
                "message": "Logs processed successfully" if signature_valid else "Signature verification failed"
            }).encode()

            sock.sendall(len(ack_message).to_bytes(4, 'big') + ack_message)
            print("✓ Acknowledgment sent to client")

        except Exception as e:
            print(f"✗ Error processing client data: {e}")
            error_msg = json.dumps({"status": "error", "message": str(e)}).encode()
            sock.sendall(len(error_msg).to_bytes(4, 'big') + error_msg)

        finally:
            sock.close()
            print(f"=== Connection with {client_addr[0]} closed ===\n")

    def start_server(self):

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"🚀 Secure Log Server started on {self.host}:{self.port}")
            print("Waiting for client connections...")

            while True:
                client_sock, client_addr = server_socket.accept()

                self.handle_client(client_sock, client_addr)

        except KeyboardInterrupt:
            print("\n🛑 Server shutdown requested")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server_socket.close()
            print("Server stopped")


def generate_keys_if_missing():

    key_files = [
        "server_private_key.pem",
        "server_public_key.pem",
        "client_private_key.pem",
        "client_public_key.pem"
    ]


    if not all(os.path.exists(f) for f in key_files):
        print("Generating RSA key pairs...")


        server_key = RSA.generate(2048)
        with open("server_private_key.pem", "wb") as f:
            f.write(server_key.export_key())
        with open("server_public_key.pem", "wb") as f:
            f.write(server_key.publickey().export_key())


        client_key = RSA.generate(2048)
        with open("client_private_key.pem", "wb") as f:
            f.write(client_key.export_key())
        with open("client_public_key.pem", "wb") as f:
            f.write(client_key.publickey().export_key())

        print("✓ Key pairs generated successfully")
        print("📋 Distribute these files:")
        print("   - client_private_key.pem → Client")
        print("   - client_public_key.pem → Server")
        print("   - server_public_key.pem → Client")
        print("   - server_private_key.pem → Server (keep secure!)")


if __name__ == "__main__":

    generate_keys_if_missing()


    server = SecureLogServer()
    server.start_server()