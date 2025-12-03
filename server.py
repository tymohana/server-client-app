# Server

import os, socket, structure

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
class SecureLogServer:
    def __init__(self, ip="127.0.0.1", port=8080):
        self.ip = ip
        self.port = port
        self.load_keys()

    def load_keys(self):
        self.server_priv = RSA.import_key(open("server_private_key.pem", "rb").read())
        self.client_pub = RSA.import_key(open("client_public_key.pem", "rb").read())
        print("Keys loaded")

    def receive_exact(self, sock, length):
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Socket closed")
            data += chunk
        return data

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

            with open("received_file.txt", "wb") as f:
                f.write(logs)

            print(f"SUCCESS → received_file.txt ({len(logs)} bytes)")

            conn.sendall(len(b"OK").to_bytes(4, "big") + b"OK")

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
            self.handle(conn, addr)


#KEY GENERATOR
if not os.path.exists("server_private_key.pem"):
    print("Generating keys...")
    k = RSA.generate(2048)
    open("server_private_key.pem", "wb").write(k.export_key())
    open("server_public_key.pem", "wb").write(k.publickey().export_key())
    c = RSA.generate(2048)
    open("client_private_key.pem", "wb").write(c.export_key())
    open("client_public_key.pem", "wb").write(c.publickey().export_key())
    print("Keys ready!")

if __name__ == "__main__":

    SecureLogServer().start()
