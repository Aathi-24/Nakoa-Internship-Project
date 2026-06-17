import socket
import time
 
target = input("Enter an IP or Domain : ")

start = time.time()
for port in range(1,101):
    sock = socket.socket()
    sock.settimeout(1)

    try:
        result = sock.connect_ex((target,port))
    except:
        pass

    if result == 0:
        print(f"Port {port} is open")

    sock.close()

end = time.time()
print("Scan completed in ", end - start, "seconds")

