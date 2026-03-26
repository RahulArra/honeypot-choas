import os
import socket
import threading
import paramiko
import time

from core.config import SSH_HOST, SSH_PORT, SESSION_TIMEOUT_SECONDS, MAX_COMMAND_LENGTH
from core.ssh.session_manager import SessionManager
from core.filesystem.virtual_fs import VirtualFileSystem
from core.database.queries import insert_command
from core.intelligence.classifier import classify_command
from core.intelligence.threat_service import handle_threat_detection

KEY_FILE = "fake_ssh_rsa.key"

if not os.path.exists(KEY_FILE):
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

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True


def handle_client(client_socket, address):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    server = SSHServer()

    session_manager = None
    channel = None
    session_id = None

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return

        session_manager = SessionManager()
        session_id = session_manager.create_session(address[0])

        vfs = VirtualFileSystem()

        channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")

        buffer = ""
        last_activity = time.time()

        while True:

            # Timeout
            if time.time() - last_activity > SESSION_TIMEOUT_SECONDS:
                channel.send("\r\nSession timed out due to inactivity.\r\n")
                session_manager.end_session(session_id, status="timeout")
                break

            if not channel.recv_ready():
                time.sleep(0.1)
                continue

            data = channel.recv(1024)
            if not data:
                break

            last_activity = time.time()
            text = data.decode("utf-8", errors="ignore")

            for char in text:
                # 1. Handle Enter (Carriage Return / Newline)
                if char in ("\r", "\n"):
                    command = buffer.strip()
                    buffer = ""
                    channel.send("\r\n")

                    if command:
                        session_manager.register_command(session_id)
                        
                        # 1. Parse Command
                        parts = command.split()
                        cmd = parts[0]
                        args = parts[1:] if len(parts) > 1 else []

                        # 2. Execute VFS Logic
                        output = ""
                        if cmd == "ls": output = vfs.list_dir()
                        elif cmd == "pwd": output = vfs.pwd()
                        elif cmd == "cd": output = vfs.cd(args[0]) if args else ""
                        elif cmd == "rmdir": output = vfs.rm(args[0]) if args else ""
                        elif cmd == "mkdir": output = vfs.mkdir(args[0]) if args else ""
                        elif cmd == "touch": output = vfs.touch(args[0]) if args else ""
                        elif cmd == "rm": output = vfs.rm(args[0]) if args else ""
                        elif cmd == "cat": output = vfs.cat(args[0]) if args else ""
                        else: output = f"bash: {cmd}: command not found"

                        # 3. Log Command
                        supported_commands = ["ls", "pwd", "cd", "mkdir", "touch", "rm", "cat", "rmdir", "chmod", "wget", "sudo"]
                        response_type = "rule" if cmd in supported_commands else "unknown"
                        
                        command_id = insert_command(
                            session_id=session_id,
                            raw_input=command,
                            parsed_command=cmd,

                            response_type=response_type,
                            response_text=output
                        )

                        # 4. Handle Intelligence & Adaptive Score
                        # 4. Handle Intelligence & Adaptive Score
                        try:
                            threat_status = handle_threat_detection(session_id, command_id, command)
                            # Use AI-generated shell response for unknown commands
                            if threat_status.get("shell_response") and cmd not in ["ls", "pwd", "cd", "mkdir", "touch", "rm", "cat", "rmdir"]:
                                if not output or output.startswith("bash:"):
                                    output = threat_status["shell_response"]
                        except Exception as e:
                            print(f"ERROR: handle_threat_detection failed: {e}")
                            threat_status = {"detected": False, "chaos_level": 1}
                        # 5. WEEK 3 PREVIEW: Apply Chaos (Latency)
                        chaos_level = threat_status.get("chaos_level", 1)
                        if chaos_level == 2:
                            time.sleep(2)  # Medium Chaos: 2s delay
                        elif chaos_level == 3:
                            time.sleep(5)  # High Chaos: 5s delay

                        # 6. Send Output
                        if output:
                            channel.send(output + "\r\n")

                    channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")
                elif char in ("\x7f", "\x08"):
                    if len(buffer) > 0:
                        buffer = buffer[:-1]
                        # The sequence: move cursor back, print space to erase, move back again
                        channel.send("\b \b")

                # 3. Handle Ctrl+C (Interrupt)
                elif char == "\x03":
                    channel.send("^C\r\n")
                    buffer = ""
                    channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")

                # 4. Handle Tab (Autocomplete - simplified for now)
                elif char == "\t":
                    # For now, just ignore or add a bell sound
                    channel.send("\x07")
                else:
                    if len(buffer) < MAX_COMMAND_LENGTH:
                        buffer += char
                        channel.send(char)
                    else:
                        channel.send("\r\nCommand too long (max 512 chars).\r\n")
                        buffer = ""
                        channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")

    except Exception as e:
        print(f"Connection error: {e}")

    finally:
        if session_manager and session_id:
            session_manager.end_session(session_id)

        if channel:
            channel.close()

        transport.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SSH_HOST, SSH_PORT))
    server_socket.listen(100)

    print(f"[*] SSH Honeypot (Week 1 Final) running on {SSH_HOST}:{SSH_PORT}")

    while True:
        client, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.daemon = True
        thread.start()