import pyshark
import numpy as np
import pandas as pd
import sys
import asyncio

# --- COMPLETE PYTHON 3.12+ / 3.14 ASYNCIO PATCH FOR PYSHARK ---
class MockChildWatcher:
    def attach_loop(self, loop): pass
    def add_child_handler(self, pid, callback, *args): pass
    def remove_child_handler(self, pid): pass
    def close(self): pass
    def is_active(self): return True

asyncio.SafeChildWatcher = MockChildWatcher
asyncio.get_child_watcher = lambda: MockChildWatcher()
asyncio.set_child_watcher = lambda watcher: None

try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())
# --------------------------------------------------------------

"""
Reprocesses an existing PCAP file into WINDOWED flow features, using the
exact same logic as live_daemon.py's process_live_window(). This fixes
the train/serve mismatch where CICFlowMeter computed Flow Duration over
each connection's entire lifetime (hours, for held-open Slowloris
sockets), while the live daemon can only ever observe a 10-second slice
- meaning the original offline-trained model was never seeing feature
magnitudes comparable to what it receives at inference time.

Usage:
    python3 generate_windowed_dataset.py baseline_traffic.pcap 0 baseline_windowed.csv
    python3 generate_windowed_dataset.py attack_traffic.pcap 1 attack_windowed.csv

Args: <pcap_path> <label 0-or-1> <output_csv>
"""

WINDOW_SIZE = 10  # seconds - MUST match live_daemon.py's WINDOW_SIZE


def extract_windowed_features(pcap_path, label):
    print(f"[+] Reading {pcap_path} ...")
    cap = pyshark.FileCapture(pcap_path, display_filter='tcp')

    rows = []
    window_start = None
    flow_data = {}

    def flush_window():
        """Compute features for every IP active in the just-closed window,
        identical logic to live_daemon.py's process_live_window()."""
        for ip, data in flow_data.items():
            timestamps = data['timestamps']
            if len(timestamps) < 2:
                continue

            flow_duration = (timestamps[-1] - timestamps[0]) * 1000
            iats = np.diff(timestamps) * 1000
            fwd_iat_mean = float(np.mean(iats)) if len(iats) > 0 else 0.0
            fwd_iat_std = float(np.std(iats)) if len(iats) > 0 else 0.0
            bwd_iat_mean = 0.0  # same limitation as the live daemon
            bwd_iat_std = 0.0

            rows.append({
                'Flow Duration': flow_duration,
                'Fwd IAT Mean': fwd_iat_mean,
                'Bwd IAT Mean': bwd_iat_mean,
                'Fwd IAT Std': fwd_iat_std,
                'Bwd IAT Std': bwd_iat_std,
                'SYN Flag Count': data['syn_count'],
                'ACK Flag Count': data['ack_count'],
                'Label': label
            })

    packet_count = 0
    for pkt in cap:
        packet_count += 1
        try:
            if hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
            elif hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
            else:
                continue

            pkt_time = float(pkt.sniff_timestamp)

            if window_start is None:
                window_start = pkt_time

            # Window boundary crossed - flush and start a new window
            if pkt_time - window_start >= WINDOW_SIZE:
                flush_window()
                flow_data = {}
                window_start = pkt_time

            is_syn = hasattr(pkt.tcp, 'flags_syn') and pkt.tcp.flags_syn == '1'
            is_ack = hasattr(pkt.tcp, 'flags_ack') and pkt.tcp.flags_ack == '1'

            if src_ip not in flow_data:
                flow_data[src_ip] = {
                    'timestamps': [pkt_time],
                    'syn_count': 1 if is_syn else 0,
                    'ack_count': 1 if is_ack else 0,
                }
            else:
                flow_data[src_ip]['timestamps'].append(pkt_time)
                flow_data[src_ip]['syn_count'] += 1 if is_syn else 0
                flow_data[src_ip]['ack_count'] += 1 if is_ack else 0

            if packet_count % 5000 == 0:
                print(f"    ... processed {packet_count} packets")

        except AttributeError:
            continue

    flush_window()  # flush final partial window
    cap.close()

    print(f"[+] Done. {packet_count} packets -> {len(rows)} windowed flow rows.")
    return pd.DataFrame(rows)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 generate_windowed_dataset.py <pcap_path> <label 0|1> <output_csv>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    label = int(sys.argv[2])
    output_csv = sys.argv[3]

    df = extract_windowed_features(pcap_path, label)
    df.to_csv(output_csv, index=False)
    print(f"[+] Saved {df.shape[0]} rows to {output_csv}")
    if df.shape[0] > 0:
        print(df.describe())