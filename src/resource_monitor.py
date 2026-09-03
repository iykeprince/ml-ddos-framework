import psutil
import time
import csv
import sys
import os

"""
Run this in a SEPARATE terminal, alongside live_daemon.py, on the Victim
Node. It finds the running live_daemon.py process and logs its CPU% and
RAM usage every second to a CSV, which you then summarize (mean CPU,
peak RAM) for Table 4.3.

Usage:
    sudo python3 resource_monitor.py <output_csv_name>

Example:
    sudo python3 resource_monitor.py rf_resource_log.csv
    ... (run your RF daemon + Slowloris attack, then Ctrl+C this) ...
    sudo python3 resource_monitor.py svm_resource_log.csv
    ... (swap MODEL_CHOICE to 'svm' in the daemon, rerun) ...
"""


def find_daemon_pid():
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info['cmdline'] or []
            if any('live_daemon.py' in arg for arg in cmdline):
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def monitor(output_csv, interval_seconds=1.0):
    pid = find_daemon_pid()
    if pid is None:
        print("[!] Could not find a running live_daemon.py process. "
              "Start the daemon first, then run this monitor.")
        sys.exit(1)

    print(f"[+] Found live_daemon.py running as PID {pid}")
    proc = psutil.Process(pid)

    # First call to cpu_percent() always returns 0.0 - prime it
    proc.cpu_percent(interval=None)
    time.sleep(interval_seconds)

    rows = []
    print(f"[+] Logging CPU%/RAM every {interval_seconds}s to {output_csv}. Press Ctrl+C to stop.\n")

    try:
        while True:
            cpu = proc.cpu_percent(interval=None)
            mem_mb = proc.memory_info().rss / (1024 * 1024)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            rows.append((timestamp, cpu, mem_mb))
            print(f"[{timestamp}] CPU: {cpu:5.1f}% | RAM: {mem_mb:7.1f} MB")
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\n[-] Stopped. Writing CSV...")
    except psutil.NoSuchProcess:
        print("\n[-] Daemon process ended. Writing CSV...")

    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'cpu_percent', 'ram_mb'])
        writer.writerows(rows)

    if rows:
        cpu_values = [r[1] for r in rows]
        ram_values = [r[2] for r in rows]
        print(f"\n=== SUMMARY ({output_csv}) ===")
        print(f"Mean CPU: {sum(cpu_values)/len(cpu_values):.1f}%")
        print(f"Peak CPU: {max(cpu_values):.1f}%")
        print(f"Mean RAM: {sum(ram_values)/len(ram_values):.1f} MB")
        print(f"Peak RAM: {max(ram_values):.1f} MB")


if __name__ == "__main__":
    output_file = sys.argv[1] if len(sys.argv) > 1 else "resource_log.csv"
    monitor(output_file)