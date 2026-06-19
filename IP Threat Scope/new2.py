import socket

target = "scanme.nmap.org"
port = 22

sock = socket.socket()
sock.settimeout(3)

sock.connect((target, port))

banner = sock.recv(1024)

print(banner.decode())

sock.close()