import os
import socket
import threading
import paramiko
from core.config import SSH_HOST, SSH_PORT
from core.ssh.session_manager import SessionManager

KEY_FILE = "fake_ssh_rsa.key"
if not os.path.exists(KEY_FILE):
    print("Generating new RSA key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)

HOST_KEY = paramiko.RSAKey.from_private_key_file(KEY_FILE)

class SSHServer(paramiko.ServerInterface):

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_shell_request(self, channel):
        return True

def handle_client(client_socket, address):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    server = SSHServer()
    transport.start_server(server=server)

    channel = transport.accept(20)
    if channel is None:
        transport.close()

        return

    session_manager = SessionManager()
    session_id = session_manager.create_session(address[0])

    channel.send(f"Welcome to Fake SSH\nSession ID: {session_id}\n")
    channel.send("root@honeypot:~$ ")

    buffer = ""

    try:
        while True:
            data = channel.recv(1024)
            if not data:
                break

            text = data.decode("utf-8")

            for char in text:

                # Handle Enter (Windows sends \r)
                if char in ("\r", "\n"):

                    command = buffer.strip()
                    buffer = ""

                    channel.send("\r\n")

                    if command:
                        session_manager.register_command(session_id)
                        channel.send("Command received\r\n")

                    channel.send("root@honeypot:~$ ")

                else:
                    buffer += char
                    channel.send(char)



    except Exception:
        pass
    finally:
        session_manager.end_session(session_id)
        channel.close()
        transport.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SSH_HOST, SSH_PORT))
    server_socket.listen(100)

    print(f"SSH Honeypot running on {SSH_HOST}:{SSH_PORT}")

    while True:
        client, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.daemon = True
        thread.start()