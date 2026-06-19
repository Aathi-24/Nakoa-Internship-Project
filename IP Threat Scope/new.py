import socket
import threading
import time

target = input("Enter an IP or Domain : ")

start = time.time()

open_ports = []
lock = threading.Lock()

def scan_port(port):
    sock = socket.socket()
    sock.settimeout(1)
    try:
        result = sock.connect_ex((target,port))
        banner = get_banner(sock)
    except Exception:
        result = -1
    if result == 0:
        with lock:
            open_ports.append(port)
    sock.close()

def get_banner(sock):

    try:
        banner = sock.recv(1024)
        return banner.decode().strip()
    except:
        return "No Banner"

if __name__ == "__main__":
    threads = []

    for port in range(1, 101):
        t = threading.Thread(
            target = scan_port,
            args = (port,)
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end = time.time()

    print("-----------------------------Summary------------------------------------")
    print()
    print("Open Ports Found : ", len(open_ports))
    print()
    open_ports.sort()

    for port in open_ports:
        try:
            server = socket.getservbyport(port)
        except Exception:
            server = "Unknown"
        
        print(port, "        ", server)

    print()
    print("Scan completed in %.2f seconds" %(end - start))