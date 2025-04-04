from modules import port_scanner, brute_forcer

def main():
    print("Penetration Testing Toolkit")
    print("1. Port Scanner")
    print("2. SSH Brute Forcer")
    choice = input("Select module: ")

    if choice == "1":
        target = input("Enter target IP: ")
        ports = list(map(int, input("Enter ports (comma-separated): ").split(',')))
        port_scanner.scan_ports(target, ports)
    
    elif choice == "2":
        host = input("Target IP: ")
        username = input("Username: ")
        path = input("Path to password file: ")
        with open(path, 'r') as f:
            passwords = f.readlines()
        brute_forcer.ssh_brute_force(host, username, passwords)

if __name__ == "__main__":
    main()

