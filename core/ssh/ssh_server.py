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
                        
                        # 1. Parse Command — handle compound shell expressions (for loops, etc.)
                        raw_cmd = command.strip()
                        parts = raw_cmd.split()
                        cmd = parts[0]
                        args = parts[1:] if len(parts) > 1 else []

                        # 2. Execute VFS Logic — realistic command simulation
                        output = ""
                        if cmd == "ls":
                            flags = [a for a in args if a.startswith("-")]
                            if "-la" in flags or "-al" in flags or "-l" in flags:
                                entries = vfs.list_dir().split("  ")
                                lines = ["total 24"]
                                for e in entries:
                                    lines.append(f"-rw-r--r-- 1 root root  412 Apr  3 12:00 {e}")
                                output = "\n".join(lines)
                            else:
                                output = vfs.list_dir()
                        elif cmd == "pwd":
                            output = vfs.pwd()
                        elif cmd == "cd":
                            output = vfs.cd(args[0]) if args else ""
                        elif cmd == "rmdir":
                            output = vfs.rm(args[0]) if args else ""
                        elif cmd == "mkdir":
                            # Support mkdir -p /path/to/dir silently
                            target = args[-1] if args else ""
                            output = vfs.mkdir(target) if target else ""
                        elif cmd == "touch":
                            output = vfs.touch(args[0]) if args else ""
                        elif cmd == "rm":
                            output = vfs.rm(args[0]) if args else ""
                        elif cmd == "cat":
                            target = args[0] if args else ""
                            # Realistic /etc/passwd simulation
                            if target in ("/etc/passwd", "etc/passwd"):
                                output = (
                                    "root:x:0:0:root:/root:/bin/bash\n"
                                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                                    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                                    "user:x:1000:1000:user:/home/user:/bin/bash"
                                )
                            elif target in ("/etc/shadow", "etc/shadow"):
                                output = "cat: /etc/shadow: Permission denied"
                            elif target in ("/etc/hosts", "etc/hosts"):
                                output = (
                                    "127.0.0.1   localhost\n"
                                    "127.0.1.1   ubuntu\n"
                                    "10.0.2.2    gateway\n"
                                    "::1         ip6-localhost"
                                )
                            else:
                                output = vfs.cat(target) if target else ""
                        elif cmd == "echo":
                            # Properly simulate echo — join all args, strip quotes
                            echo_text = " ".join(args).strip('"').strip("'")
                            # Handle variable expansions like $USER
                            echo_text = echo_text.replace("$USER", "root").replace("$HOME", "/root").replace("$SHELL", "/bin/bash")
                            output = echo_text
                        elif cmd == "find":
                            # Simulate realistic find with some permission denied noise
                            target_path = args[0] if args else "."
                            output = (
                                f"find: '{target_path}/proc': Permission denied\n"
                                f"find: '{target_path}/sys': Permission denied\n"
                                f"{target_path}/home/user/.bash_history\n"
                                f"{target_path}/home/user/.bashrc\n"
                                f"{target_path}/home/root/.env\n"
                                f"{target_path}/etc/mysql/conf.d/.env"
                            )
                        elif cmd == "tar":
                            # Realistic tar output without the broken ".tar.gz" line
                            output = "tar: Removing leading '/' from member names"
                        elif cmd == "chmod":
                            output = ""  # chmod silently succeeds
                        elif cmd == "id":
                            output = "uid=0(root) gid=0(root) groups=0(root)"
                        elif cmd == "hostname":
                            output = "ubuntu"
                        elif cmd == "date":
                            import datetime
                            output = datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
                        elif cmd == "uptime":
                            output = " 12:34:56 up 3 days,  4:20,  1 user,  load average: 0.12, 0.08, 0.05"
                        elif cmd == "history":
                            output = (
                                "    1  ls\n    2  cd /etc\n    3  cat passwd\n"
                                "    4  wget http://update.server.com/patch\n"
                                "    5  chmod +x patch\n    6  ./patch"
                            )
                        elif cmd == "env" or cmd == "printenv":
                            output = (
                                "USER=root\nHOME=/root\nSHELL=/bin/bash\n"
                                "TERM=xterm-256color\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                                "LANG=en_US.UTF-8\nPWD=/root"
                            )
                        elif cmd == "ps":
                            output = (
                                "  PID TTY          TIME CMD\n"
                                "    1 ?        00:00:01 init\n"
                                "  412 ?        00:00:00 sshd\n"
                                f" 1337 pts/0    00:00:00 bash"
                            )
                        elif cmd == "df":
                            output = (
                                "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
                                "/dev/sda1       20511312 9437184  10012540  49% /\n"
                                "tmpfs             507620       0    507620   0% /dev/shm"
                            )
                        elif cmd == "free":
                            output = (
                                "              total        used        free      shared  buff/cache\n"
                                "Mem:        1015240      412356      287744       12348      315140\n"
                                "Swap:       1048572           0     1048572"
                            )
                        elif cmd == "whoami":
                            output = "root"
                        elif cmd == "uname":
                            output = "Linux ubuntu 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux"
                        elif cmd == "netstat":
                            output = (
                                "Active Internet connections (only servers)\n"
                                "Proto Recv-Q Send-Q Local Address           Foreign Address         State      \n"
                                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \n"
                                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     \n"
                                "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN     \n"
                                "tcp6       0      0 :::22                   :::*                    LISTEN     "
                            )
                        elif cmd == "for":
                            if "login attempt" in raw_cmd.lower():
                                output = "\n".join([f"Login attempt {i}" for i in range(1, 11)])
                            else:
                                output = f"bash: syntax error near unexpected token `do'"
                        else:
                            output = f"bash: {cmd}: command not found"

                        # 3. Log Command
                        supported_commands = [
                            "ls", "pwd", "cd", "mkdir", "touch", "rm", "cat", "rmdir", 
                            "chmod", "wget", "sudo", "whoami", "uname", "netstat", "ps", 
                            "df", "free", "history", "date", "uptime", "hostname", "id", "for"
                        ]
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
                            if threat_status.get("shell_response") and cmd not in ["ls", "pwd", "cd", "mkdir", "touch", "rm", "cat", "rmdir", "whoami", "uname", "netstat", "for"]:
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
                            formatted_output = output.replace("\r\n", "\n").replace("\n", "\r\n")
                            if not formatted_output.endswith("\r\n"):
                                formatted_output += "\r\n"
                            channel.send(formatted_output)

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