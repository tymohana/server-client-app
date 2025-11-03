# server-client-app
A client-server application designed to securely transmit log files over a network using end-to-end encryption and digital signatures.  This project ensures the confidentiality, integrity, and authenticity of log data exchanged between a client and a central log server.
This project is a secure log transfer system made up of two main parts, a client and a server. The goal is to safely send log files from the client to the server so that no one can read or change the data while it’s being transferred. To do this, the program uses a mix of encryption and digital signatures to protect the information.

On the client side, the program first loads two keys, the client’s private key and the server’s public key. It then reads the contents of a local log file called logs.txt.(This text file has been  chose only for testing perpose) Before sending the data, the client creates a digital signature using its private key. This signature proves that the logs really came from the client and that they haven’t been changed.

Next, the client encrypts the logs using AES encryption (a strong symmetric encryption method). AES uses a random secret key each time. This key is then protected using RSA encryption with the server’s public key. This way, only the server can unlock the AES key and read the logs. The client then sends all the encrypted data , including the encrypted AES key, the encrypted logs, the digital signature, and some extra values needed for decryption, over a TCP socket to the server.

On the server side, the program listens for incoming connections from clients. When a client connects, the server receives all the pieces of data that were sent. It first decrypts the AES key using its private RSA key. Once it has the AES key, it can decrypt the actual logs. The server then verifies the client’s digital signature using the client’s public key to make sure the logs are genuine and haven’t been tampered with.

If the verification is successful, the server securely stores the logs in a special folder, along with metadata like the time received, the client’s IP address, and whether the signature was valid. The server also sends a message back to the client to confirm that the logs were received and processed correctly.

The system supports both manual sending, where the user can choose to send logs right away, and automatic sending, where the client sends logs every day at a set time (for example, 17:00). This makes it flexible for different use cases, such as continuous security monitoring or daily log backups.
