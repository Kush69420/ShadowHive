import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import time
from pathlib import Path
import traceback


# ==========================
# CONFIGURATION
# ==========================

BASE_DIR = Path(__file__).parent.parent
SERVER_KEY_PATH = BASE_DIR / 'ssh_honeypy' / 'static' / 'server.key'

LOG_DIR = BASE_DIR / 'ssh_honeypy' / 'log_files'
LOG_DIR.mkdir(parents=True, exist_ok=True)

CREDS_LOG_FILE = LOG_DIR / 'creds_audits.log'
CMD_LOG_FILE = LOG_DIR / 'cmd_audits.log'

SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
WELCOME_BANNER = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"

LOG_MAX_SIZE = 2_000_000  # 2 MB before rotation
LOG_BACKUP_COUNT = 5


# ==========================
# LOGGING
# ==========================

def setup_logger(name: str, file_path: Path) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(file_path, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)

    return logger


funnel_logger = setup_logger('FunnelLogger', CMD_LOG_FILE)
creds_logger = setup_logger('CredsLogger', CREDS_LOG_FILE)


# ==========================
# COMMAND HANDLER
# ==========================

COMMAND_RESPONSES = {
    b'pwd': b"\\usr\\local",
    b'whoami': b"corpuser1",
    b'ls': b"jumpbox1.conf",
    b'cat jumpbox1.conf': b"Go to deeboodah.com",
}

def handle_command(command: bytes, client_ip: str) -> bytes:
    """Return fake output for a given command."""
    command = command.strip()

    if command == b'exit':
        return b"\n Goodbye!\n"

    response = COMMAND_RESPONSES.get(command, command)
    funnel_logger.info(f"Command {command.decode(errors='ignore')} executed by {client_ip}")
    return b"\n" + response + b"\r\n"


# ==========================
# SSH SERVER CLASS
# ==========================

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with username={username}, password={password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')

        if self.input_username and self.input_password:
            return paramiko.AUTH_SUCCESSFUL if (username == self.input_username and password == self.input_password) else paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


# ==========================
# SHELL EMULATION
# ==========================

def emulated_shell(channel, client_ip):
    """Fake shell that processes attacker commands."""
    channel.send(b"corporate-jumpbox2$ ")
    command = b""

    while True:
        try:
            char = channel.recv(1)
            if not char:
                channel.close()
                break

            channel.send(char)  # echo
            command += char

            if char == b"\r":
                response = handle_command(command, client_ip)
                channel.send(response)

                if command.strip() == b'exit':
                    channel.close()
                    break

                channel.send(b"corporate-jumpbox2$ ")
                command = b""

        except Exception as e:
            funnel_logger.error(f"Shell error with {client_ip}: {e}\n{traceback.format_exc()}")
            channel.close()
            break


# ==========================
# CLIENT HANDLER
# ==========================

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        host_key = paramiko.RSAKey(filename=SERVER_KEY_PATH)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
            return

        if tarpit:
            endless_banner = WELCOME_BANNER * 100
            for char in endless_banner:
                channel.send(char)
                time.sleep(8)
        else:
            channel.send(WELCOME_BANNER)

        emulated_shell(channel, client_ip)

    except Exception as e:
        funnel_logger.error(f"Client handler exception: {e}\n{traceback.format_exc()}")

    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()


# ==========================
# HONEYPOT RUNNER
# ==========================

def honeypot(address="0.0.0.0", port=2222, username=None, password=None, tarpit=False):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)

    print(f"SSH honeypot listening on {address}:{port}")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(
                target=client_handle,
                args=(client, addr, username, password, tarpit),
                daemon=True
            )
            ssh_honeypot_thread.start()
        except Exception as e:
            funnel_logger.error(f"Failed to accept client connection: {e}\n{traceback.format_exc()}")
