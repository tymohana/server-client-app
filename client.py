import socket
import time
import schedule
import threading
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from datetime import datetime
import os

class Log_Client:
    def __init__(self):
        self.server_ip = "127.0.0.1"
        self.server_port = 8080
    def load_keys(self):
        with open("client_private_key.pem", "rb") as f:
            self.client_private_key = RSA.import_key(f.read())
        with open("server_public_key.pem", "rb") as f:
            self.server_public_key = RSA.import_key(f.read())

    def read_logs(self):
        with open("logs.txt", "rb") as f:
            return f.read()


    # Creating the signature using client private key
    def sign_logs(self, logs):
        hash_obj = SHA512.new(logs)
        signer = PKCS1_v1_5.new(self.client_private_key)
        signature = signer.sign(hash_obj)
        return signature
    # Encrypt logs using AES key
    def encrypt_logs(self, logs):
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(logs)
        return ciphertext, tag, cipher_aes.nonce , aes_key

    #Encrypt AES key with RSA
    def encrypt_aes_key(self, aes_key):
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        return encrypted_key

    def send_data(self, encrypted_data):
        encrypted_aes_key , encrypted_logs , tag, nonce ,signature = encrypted_data
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server_ip, self.server_port))
        pieces = [encrypted_aes_key, encrypted_logs, tag,nonce, signature]
        for piece in pieces:
            length = len(piece).to_bytes(4, 'big')
            s.sendall(length + piece)
        s.close()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Logs sent successfully")

    def send_logs(self):
        try:
            self.load_keys()
            logs = self.read_logs()
            print(f"Read {len(logs)} bytes of logs")

            signature = self.sign_logs(logs)
            print("Signature created")

            encrypted_logs, tag, nonce, aes_key = self.encrypt_logs(logs)
            print("Logs encrypted with AES-256")

            encrypted_aes_key = self.encrypt_aes_key(aes_key)
            print("AES key encrypted with RSA")

            encrypted_data = (encrypted_aes_key, encrypted_logs, tag, nonce, signature)
            self.send_data(encrypted_data)
        except Exception as e:
            print(f"Error:{e}")


    def manual_send(self):
        print("Sending logs manually...")
        self.send_logs()

    def auto_send(self):
        print(" Auto_send started. Logs will be sent at 17:00 every day.")
        while True:
            now = datetime.now()
            if now.hour == 17 and now.minute == 0:
                print(f"\n[{now.strftime('%H:%M:%S')}] Scheduled send triggered!")
                self.send_logs()
                time.sleep(60)
            else:
                next_check = f"Next check in 30 seconds (current time: {now.strftime('%H:%M:%S')})"
                print(next_check, end='\r')
                time.sleep(30)


def main():
    client = Log_Client()
    print("Please select what service you would like to use:")
    print("1. Send logs now")
    print("2. Start auto_send(daily at 17:00)")
    print("3. Exit")

    while True:
        choice = input("\nChoose option (1-3): ").strip()
        if choice == "1":
            client.manual_send()
        elif choice == "2":
            auto_thread = threading.Thread(target=client.auto_send, daemon=True)
            auto_thread.start()
            input("Auto-send running in background. You can still use manual send.")

        elif choice == "3":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()