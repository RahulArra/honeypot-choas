import os
import socket
import threading
import paramiko
import time
import datetime
from core.config import SSH_HOST, SSH_PORT, SESSION_TIMEOUT_SECONDS, MAX_COMMAND_LENGTH
from core.ssh.session_manager import SessionManager
from core.filesystem.virtual_fs import VirtualFileSystem
from core.database.queries import insert_command
from core.parser.input_parser import normalize_input, sanitize_input
from core.parser.command_classifier import classify_command
from core.engine.rule_engine import RuleEngine
from core.utils.logger import logger
from core.intelligence.threat_service import handle_threat_detection
from core.utils.latency import inject_latency

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

    session_manager = SessionManager()
    channel = None
    session_id = None

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return

        session_id = session_manager.create_session(address[0])
        vfs = VirtualFileSystem()
        engine = RuleEngine(vfs)
        
        logger.info(f"New session {session_id} started for {address[0]}")
        
        login_time = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")

        channel.send(
            f"Last login: {login_time} from {address[0]}\r\n"
        )
        channel.send("Ubuntu 22.04.4 LTS\r\n")
        channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")

        buffer = ""
        last_activity = time.time()

        while True:
            # 1. DEFENSIVE: Check if transport or channel died unexpectedly
            if not transport.is_active():
                logger.info(f"Transport dead for {address[0]}")
                break
            
            if channel.closed or channel.exit_status_ready():
                logger.info(f"Channel closed for {address[0]}")
                break

            # 2. Timeout Check
            if time.time() - last_activity > SESSION_TIMEOUT_SECONDS:
                channel.send("\r\nSession timed out due to inactivity.\r\n")
                session_manager.end_session(session_id, status="timeout")
                break

            # 3. Non-blocking Receive Check
            if not channel.recv_ready():
                time.sleep(0.05) # Small sleep to prevent CPU spiking
                continue

            data = channel.recv(1024)
            if not data:
                logger.info(f"EOF received from {address[0]}")
                break

            last_activity = time.time()
            text = data.decode("utf-8", errors="ignore")

            for char in text:
                if char in ("\r", "\n"):
                    command = buffer.strip()
                    buffer = ""
                    channel.send("\r\n")

                    if command:
                       
                       # 1. BRAIN: Throttling
                        try :
                            delay = session_manager.get_throttle_delay(session_id)
                            if delay > 0:
                                time.sleep(delay)

                            # 2. PARSER
                            clean_cmd = sanitize_input(command)
                            final_cmd = normalize_input(clean_cmd)

                            # 3. DECEPTION ENGINE
                            output = engine.execute(final_cmd)

                            # 4. CLASSIFICATION (for logging category)
                            category = classify_command(final_cmd)

                            # 5. LATENCY INJECTION
                            inject_latency(category)

                            # 6. DATABASE COMMAND INSERT
                            response_type = "rule"
                            response_text = output if output else ""

                            session_manager.register_command(session_id)

                            command_id = insert_command(
                                session_id,
                                final_cmd,
                                category,
                                response_type,
                                response_text
                            )

                            # 7. THREAT INTELLIGENCE (CRITICAL STEP)
                            threat_result = handle_threat_detection(
                                session_id,
                                command_id,
                                final_cmd
                            )

                            # 8. INTERACTION
                            if output:
                                channel.send(output + "\r\n")

                        except Exception as e:
                            logger.error(f"Command Error: {str(e)}")
                            channel.send(f"Error processing command: {str(e)}\r\n")

                    channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")
                
                elif char in ("\x7f", "\x08"):
                    if len(buffer) > 0:
                        buffer = buffer[:-1]
                        channel.send("\b \b")

                elif char == "\x03":
                    channel.send("^C\r\n")
                    buffer = ""
                    channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")

                elif char == "\t":
                    channel.send("\x07")
                
                else:
                    if len(buffer) < MAX_COMMAND_LENGTH:
                        buffer += char
                        channel.send(char)
                    else:
                        channel.send("\r\nCommand too long.\r\n")
                        buffer = ""
                        channel.send(f"root@honeypot:{vfs.get_prompt_path()}$ ")

    except Exception as e:
        logger.error(f"Session Error for {address[0]}: {e}")
    finally:
        # CLEANUP: Ensure NO threads or sockets are leaked
        if session_manager and session_id:
            session_manager.end_session(session_id)
        if channel:
            channel.close()
        if transport:
            transport.close()
        logger.info(f"Cleanup finished for {address[0]}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SSH_HOST, SSH_PORT))
    server_socket.listen(100)
    logger.info(f"[*] SSH Honeypot (Hardened) running on {SSH_HOST}:{SSH_PORT}")

    while True:
        client, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.daemon = True # Very important for clean exits
        thread.start()