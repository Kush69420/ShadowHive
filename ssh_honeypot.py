# Import library dependencies.
import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import time
import os
from pathlib import Path

# Constants.
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Get base directory of where user is running honeypy from.
base_dir = Path(__file__).parent.parent
print(f"Base directory: {base_dir}")

# Create directories if they don't exist
static_dir = base_dir / 'ssh_honeypy' / 'static'
log_dir = base_dir / 'ssh_honeypy' / 'log_files'

# Create directories
static_dir.mkdir(parents=True, exist_ok=True)
log_dir.mkdir(parents=True, exist_ok=True)

# File paths
server_key_path = static_dir / 'server.key'
creds_audits_log_path = log_dir / 'creds_audits.log'
cmd_audits_log_path = log_dir / 'cmd_audits.log'

# Generate RSA key if it doesn't exist
if not server_key_path.exists():
    print("Generating RSA host key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(server_key_path))
    print(f"RSA key generated at: {server_key_path}")

# Load SSH Server Host Key
try:
    host_key = paramiko.RSAKey(filename=str(server_key_path))
    print("RSA host key loaded successfully")
except Exception as e:
    print(f"Error loading host key: {e}")
    exit(1)

# Logging Format.
logging_format = logging.Formatter('%(asctime)s - %(message)s')

# Funnel (catch all) Logger.
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(cmd_audits_log_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Credentials Logger. Captures IP Address, Username, Password.
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_audits_log_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# SSH Server Class. This establishes the options for the SSH server.
class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
    
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        print(f"Auth attempt from {self.client_ip}: {username}:{password}")
        
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def emulated_shell(channel, client_ip):
    try:
        channel.send(b"corporate-jumpbox2$ ")
        command = b""
        
        while True:  
            char = channel.recv(1)
            if not char:
                print(f"Client {client_ip} disconnected")
                break
                
            channel.send(char)
            command += char
            
            # Emulate common shell commands.
            if char == b"\r":
                cmd_str = command.strip()
                print(f"Command from {client_ip}: {cmd_str}")
                
                if cmd_str == b'exit':
                    response = b"\nGoodbye!\n"
                    channel.send(response)
                    break
                elif cmd_str == b'pwd':
                    response = b"\n/usr/local\r\n"
                    funnel_logger.info(f'Command {cmd_str} executed by {client_ip}')
                elif cmd_str == b'whoami':
                    response = b"\ncorpuser1\r\n"
                    funnel_logger.info(f'Command {cmd_str} executed by {client_ip}')
                elif cmd_str == b'ls':
                    response = b"\njumpbox1.conf\r\n"
                    funnel_logger.info(f'Command {cmd_str} executed by {client_ip}')
                elif cmd_str == b'cat jumpbox1.conf':
                    response = b"\nGo to deeboodah.com\r\n"
                    funnel_logger.info(f'Command {cmd_str} executed by {client_ip}')
                else:
                    response = b"\n" + cmd_str + b": command not found\r\n"
                    funnel_logger.info(f'Command {cmd_str} executed by {client_ip}')
                
                channel.send(response)
                channel.send(b"corporate-jumpbox2$ ")
                command = b""
                
    except Exception as e:
        print(f"Shell error for {client_ip}: {e}")
    finally:
        try:
            channel.close()
        except:
            pass

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")
    
    try:
        # Initialize a Transport object using the socket connection from client.
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        # Creates an instance of the SSH server, adds the host key to prove its identity, starts SSH server.
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        # Establishes an encrypted tunnel for bidirectional communication between the client and server.
        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened.")
            return

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        
        try:
            # Endless Banner: If tarpit option is passed, then send 'endless' ssh banner.
            if tarpit:
                print(f"Tarpitting client {client_ip}")
                endless_banner = standard_banner * 100
                for char in endless_banner:
                    channel.send(char.encode())
                    time.sleep(8)
            # Standard Banner: Send generic welcome banner to impersonate server.
            else:
                channel.send(standard_banner.encode())
            
            print(f"Starting shell session for {client_ip}")
            # Send channel connection to emulated shell for interpretation.
            emulated_shell(channel, client_ip=client_ip)

        except Exception as error:
            print(f"Channel error: {error}")
            
    except Exception as error:
        print(f"Transport error: {error}")
    
    # Once session has completed, close the transport connection.
    finally:
        try:
            transport.close()
        except Exception:
            pass
        
        client.close()
        print(f"Connection closed for {client_ip}")

def honeypot(address, port, username=None, password=None, tarpit=False):
    
    # Open a new socket using TCP, bind to port.
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        socks.bind((address, port))
        print(f"Successfully bound to {address}:{port}")
    except Exception as e:
        print(f"Error binding to {address}:{port} - {e}")
        return

    # Can handle 100 concurrent connections.
    socks.listen(100)
    print(f"SSH honeypot is listening on {address}:{port}")
    print(f"Authentication: {'Required' if username and password else 'Open (any credentials accepted)'}")
    print("Waiting for connections...")

    while True: 
        try:
            # Accept connection from client and address.
            client, addr = socks.accept()
            print(f"New connection from {addr[0]}:{addr[1]}")
            
            # Start a new thread to handle the client connection.
            ssh_honeypot_thread = threading.Thread(
                target=client_handle, 
                args=(client, addr, username, password, tarpit)
            )
            ssh_honeypot_thread.daemon = True
            ssh_honeypot_thread.start()

        except KeyboardInterrupt:
            print("\nShutting down honeypot...")
            break
        except Exception as error:
            print(f"Error accepting connection: {error}")
    
    socks.close()

if __name__ == "__main__":
    # Start the honeypot
    # Change these parameters as needed
    HOST = "0.0.0.0"  # Listen on all interfaces
    PORT = 2222       # Use port 2222 (non-privileged port)
    USERNAME = None   # Set to None to accept any username
    PASSWORD = None   # Set to None to accept any password
    TARPIT = False    # Set to True to enable tarpit mode
    
    print("Starting SSH Honeypot...")
    print("Press Ctrl+C to stop")
    
    honeypot(HOST, PORT, USERNAME, PASSWORD, TARPIT)