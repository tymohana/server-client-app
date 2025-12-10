# Server

import os, socket, struct, random, time

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

            randnum = random.randint(1, 100)
            filename = f"received_file{randnum}.txt"
            with open(filename, "wb") as f:
                f.write(logs)

            print(f"SUCCESS → {filename} ({len(logs)} bytes)")

            conn.sendall(len(b"OK").to_bytes(4, "big") + b"OK")
            
            return logs

        except Exception as e:
            print(f"ERROR: {e}")
        finally:
            conn.close()

    def start(self):
        self.keygen()
        self.load_keys()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.ip, self.port))
        s.listen(1)
        print(f"\nServer LISTENING on {self.ip}:{self.port}\n")
        while True:
            conn, addr = s.accept()
            start = time.time()
            data = self.handle(conn, addr)
            size_bits = len(data) * 8
            end = time.time()
            throughput = (size_bits / (end - start)) / 1000000
            print(f"Receieved:\n{data.decode()}\n| Throughput: {throughput:.2f} MB/s")

if __name__ == "__main__":
    Server().start()