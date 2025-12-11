# Server

import os, socket, struct, random, time, threading

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

class Server:
    def __init__(self, ip="0.0.0.0", port=8080):
        self.ip = ip
        self.port = port
        
    def keygen(self):
        if not os.path.exists("server_private_key.pem"):
            print("Generating keys...")
            key = RSA.generate(2048)
            open("server_private_key.pem", "wb").write(key.export_key())
            open("server_public_key.pem", "wb").write(key.publickey().export_key())
        print("Keys generated.")
    
    def receive_exact(self, sock, length):
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Socket closed")
            data += chunk
        return data

    def load_keys(self):
        self.server_priv = RSA.import_key(open("server_private_key.pem", "rb").read())
        print("Keys loaded")

    def receive_msg(self, sock):
        length = struct.unpack(">I", self.receive_exact(sock, 4))[0]
        return self.receive_exact(sock, length)

    def decrypt_aes(self, enc_key):
        return PKCS1_OAEP.new(self.server_priv).decrypt(enc_key)

    def decrypt_logs(self, key, enc, tag, nonce):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(enc, tag)

    def verify(self, data, sig):
        h = SHA512.new(data)
        return PKCS1_v1_5.new(self.client_pub).verify(h, sig)
    
    def handle(self, conn, addr):
        print(f"\n[+] Client connected: {addr[0]}")

        try:
            # Send server public key
            server_pub = open("server_public_key.pem", "rb").read()
            conn.sendall(len(server_pub).to_bytes(4, "big") + server_pub)

            # Receive client public key
            client_pub_len = struct.unpack(">I", self.receive_exact(conn, 4))[0]
            client_pub_bytes = self.receive_exact(conn, client_pub_len)
            self.client_pub = RSA.import_key(client_pub_bytes)
            print("Client public key received")

            # Other BS
            encrypted_key = self.receive_msg(conn)
            encrypted_logs = self.receive_msg(conn)
            tag = self.receive_msg(conn)
            nonce = self.receive_msg(conn)
            signature = self.receive_msg(conn)
            aes_key = self.decrypt_aes(encrypted_key)
            logs    = self.decrypt_logs(aes_key, encrypted_logs, tag, nonce)

            if self.verify(logs, signature):
                print("Signature OK")
            else:
                print("BAD SIGNATURE")
                return

            # 1. Use AES key
            storage_key = aes_key

            # 2. Encrypt file with AES-GCM
            storage_cipher = AES.new(storage_key, AES.MODE_GCM)
            storage_ciphertext, storage_tag = storage_cipher.encrypt_and_digest(logs)
            storage_nonce = storage_cipher.nonce

            # 3. Encrypt AES key with server public RSA key
            server_pub = RSA.import_key(open('server_public_key.pem', 'rb').read())
            rsa_cipher = PKCS1_OAEP.new(server_pub)
            encrypted_storage_key = rsa_cipher.encrypt(storage_key)

            # 4. Generate filename
            randnum = random.randint(1, 9999)
            base_filename = f"{addr[0]}_{addr[1]}_received_file_{randnum}"

            # 5. Save AES-encrypted file into a dedicated `logs` directory
            logs_dir = "logs"
            os.makedirs(logs_dir, exist_ok=True)

            enc_path = os.path.join(logs_dir, base_filename + ".enc")
            keyenc_path = os.path.join(logs_dir, base_filename + ".key.enc")
            nonce_path = os.path.join(logs_dir, base_filename + ".nonce")
            tag_path = os.path.join(logs_dir, base_filename + ".tag")

            with open(enc_path, "wb") as f:
                f.write(storage_ciphertext)

            # Save RSA-encrypted AES key
            with open(keyenc_path, "wb") as f:
                f.write(encrypted_storage_key)

            # Save GCM metadata
            with open(nonce_path, "wb") as f:
                f.write(storage_nonce)

            with open(tag_path, "wb") as f:
                f.write(storage_tag)

            print("Encrypted file stored securely:")
            print(enc_path)
            print("  AES key (RSA-encrypted):", keyenc_path)
            print("  GCM tag:", tag_path)
            print("  GCM nonce:", nonce_path)

            print(f"SUCCESS → {base_filename} ({len(logs)} bytes)")

            conn.sendall(len(b"OK").to_bytes(4, "big") + b"OK")
            
            return logs

        except Exception as e:
            print(f"ERROR: {e}")
        finally:
            conn.close()

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.ip, self.port))
        s.listen(1)
        print(f"\nServer LISTENING on {self.ip}:{self.port}\n")
        while True:
            conn, addr = s.accept()
            start = time.time()
            data = self.handle(conn, addr)
            end = time.time()
            size_bits = len(data) * 8
            throughput = (size_bits / (end - start)) / 1000000
            print(f"Received: {len(data)} bytes | Throughput: {throughput:.2f} MB/s")
    
    def start_threaded(self):
        """Start server in background thread and present interactive menu."""
        self.keygen()
        self.load_keys()

        # Start server in background thread
        server_thread = threading.Thread(target=self.start, daemon=True)
        server_thread.start()
        print("\n[+] Server started in background.")
        
        # Main menu loop
        while True:
            print("\n--- Server Menu ---")
            print("1. List encrypted files")
            print("2. Decrypt a file")
            print("3. Exit")
            choice = input("Select an option: ").strip()

            if choice == '1':
                self.list_encrypted_files()

            elif choice == '2':
                enc_files = self.list_encrypted_files()
                if enc_files:
                    try:
                        idx = int(input("\nEnter file number to decrypt: "))
                        base_filename = list(enc_files.keys())[idx - 1]
                        self.decrypt_stored_file(base_filename)
                    except (ValueError, IndexError):
                        print("[-] Invalid selection.")

            elif choice == '3':
                print("Exiting...")
                break

            else:
                print("[-] Invalid option.")
        
if __name__ == '__main__':
    Server().start_threaded()