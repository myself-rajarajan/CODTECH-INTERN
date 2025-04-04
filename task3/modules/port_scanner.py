import socket

def scan_ports(target, ports):
    print(f"[+] Scanning {target}")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port}")
            else:
                print(f"[CLOSED] Port {port}")
            s.close()
        except Exception as e:
            print(f"[ERROR] Port {port}: {e}")

