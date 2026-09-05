import time
import os
import subprocess
import threading
import logging
import joblib
import numpy as np
import pandas as pd
import asyncio
import pyshark

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

# --- CONFIGURATION ---
INTERFACE = 'enp0s3'            # Victim Node interface on the isolated NAT Network
TARGET_PORT = 80
WINDOW_SIZE = 10                 # Rolling window in seconds
MODEL_CHOICE = 'random_forest'   # 'random_forest' or 'svm'

# Must exactly match FEATURE_COLUMNS in train_rf_model.py / train_svm_model.py,
# same names, same order - sklearn validates this on predict().
FEATURE_COLUMNS = [
    'Flow Duration',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Fwd IAT Std',
    'Bwd IAT Std',
    'SYN Flag Count',
    'ACK Flag Count'
]

# --- MITIGATION TUNING ---
STRIKES_REQUIRED = 2             # consecutive malicious windows required before a block
CONFIDENCE_THRESHOLD = 0.85      # min malicious-class probability to count as a strike
BLOCK_DURATION_SECONDS = 120     # blocks auto-expire; not permanent
# IPs that should never be auto-blocked regardless of classification -
# always include this host's own IP, since the BPF filter captures both
# inbound client traffic AND this server's own outbound responses on
# port 80. Without this, the daemon can misclassify its own response
# traffic as an attacking flow and block itself.
WHITELIST_IPS = {
    "10.10.10.10",  # Victim Node's own IP - NEVER remove this
    # "10.10.10.1",   # e.g. gateway
    # "10.10.10.20",  # e.g. JMeter client host
}
AUDIT_LOG_PATH = './mitigation_audit.log'

logging.basicConfig(
    filename=AUDIT_LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s %(message)s'
)

IP_STRIKES = {}
BLOCKED_IPS = set()


def load_security_artifacts(model_type):
    print(f"[+] Loading {model_type.upper()} security artifacts...")

    if model_type == 'random_forest':
        model_path = './models/random_forest.pkl'
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Missing model file at {model_path}. Run train_rf_model.py first!")
        model = joblib.load(model_path)
        scaler = None
    elif model_type == 'svm':
        model_path = './models/svm_model.pkl'
        scaler_path = './models/svm_scaler.pkl'
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            raise FileNotFoundError("Missing SVM model or scaler file! Run train_svm_model.py first!")
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
    else:
        raise ValueError("Invalid model choice! Choose 'random_forest' or 'svm'.")

    print(f"[+] {model_type.upper()} model successfully loaded into memory.")
    return model, scaler


def get_malicious_confidence(model, feature_vector):
    prediction = model.predict(feature_vector)[0]
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(feature_vector)[0]
            malicious_confidence = proba[1] if len(proba) > 1 else proba[0]
            return prediction, malicious_confidence
        except Exception:
            pass
    return prediction, (1.0 if prediction == 1 else 0.0)


def unblock_ip(ip_address):
    cmd = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
    try:
        subprocess.run(cmd, shell=True, check=True)
        msg = f"[<---] Auto-unblocked {ip_address} after {BLOCK_DURATION_SECONDS}s quarantine."
        print(f"\n{msg}\n")
        logging.info(msg)
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to remove iptables rule for {ip_address}: {e}")
        logging.info(f"FAILED auto-unblock for {ip_address}: {e}")
    finally:
        BLOCKED_IPS.discard(ip_address)
        IP_STRIKES.pop(ip_address, None)


def trigger_iptables_mitigation(ip_address, confidence, features):
    if ip_address in BLOCKED_IPS:
        return

    start_time = time.time()
    cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"

    try:
        subprocess.run(cmd, shell=True, check=True)
        mitigation_latency = (time.time() - start_time) * 1000

        BLOCKED_IPS.add(ip_address)

        print(f"\n[!!!] ALERT: ATTACK DETECTED FROM {ip_address} "
              f"(confidence={confidence:.2f}, strikes={IP_STRIKES.get(ip_address, 0)})")
        print(f"[--->] MITIGATION: temporary DROP rule for {ip_address} "
              f"(auto-unblocks in {BLOCK_DURATION_SECONDS}s)")
        print(f"[--->] SUBPROCESS EXECUTION LATENCY: {mitigation_latency:.2f} ms\n")

        logging.info(
            f"BLOCK ip={ip_address} confidence={confidence:.3f} "
            f"latency_ms={mitigation_latency:.2f} features={features}"
        )

        timer = threading.Timer(BLOCK_DURATION_SECONDS, unblock_ip, args=[ip_address])
        timer.daemon = True
        timer.start()

    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to execute iptables command (Expected on macOS): {e}")
        logging.info(f"FAILED block for {ip_address}: {e}")


def process_live_window(packets, model, scaler, model_type):
    if not packets:
        return

    flow_data = {}

    for pkt in packets:
        try:
            if hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
            elif hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
            else:
                continue

            pkt_time = float(pkt.sniff_timestamp)
            is_syn = hasattr(pkt.tcp, 'flags_syn') and pkt.tcp.flags_syn == '1'
            is_ack = hasattr(pkt.tcp, 'flags_ack') and pkt.tcp.flags_ack == '1'

            if src_ip not in flow_data:
                flow_data[src_ip] = {
                    'timestamps': [pkt_time],
                    'syn_count': 1 if is_syn else 0,
                    'ack_count': 1 if is_ack else 0,
                    'fwd_pkts': 1,
                }
            else:
                flow_data[src_ip]['timestamps'].append(pkt_time)
                flow_data[src_ip]['syn_count'] += 1 if is_syn else 0
                flow_data[src_ip]['ack_count'] += 1 if is_ack else 0
                flow_data[src_ip]['fwd_pkts'] += 1
        except AttributeError:
            continue

    for ip, data in flow_data.items():
        if ip in WHITELIST_IPS or ip in BLOCKED_IPS:
            continue

        timestamps = data['timestamps']
        if len(timestamps) < 2:
            continue

        flow_duration = (timestamps[-1] - timestamps[0]) * 1000
        iats = np.diff(timestamps) * 1000
        fwd_iat_mean = float(np.mean(iats)) if len(iats) > 0 else 0.0
        fwd_iat_std = float(np.std(iats)) if len(iats) > 0 else 0.0

        # NOTE / KNOWN LIMITATION: this capture only observes packets sourced
        # from `ip` (the client), so true backward (server->client) flow
        # timing can't be derived from this single grouping without also
        # tracking response packets by destination IP. Bwd IAT is therefore
        # held at 0 in real-time inference. Document this explicitly in your
        # Threats to Validity / Limitations section (Section 5.3) - it's a
        # genuine gap between the offline feature set and what the live
        # daemon can compute without a full bidirectional flow tracker.
        bwd_iat_mean = 0.0
        bwd_iat_std = 0.0

        feature_vector = pd.DataFrame([{
            'Flow Duration': flow_duration,
            'Fwd IAT Mean': fwd_iat_mean,
            'Bwd IAT Mean': bwd_iat_mean,
            'Fwd IAT Std': fwd_iat_std,
            'Bwd IAT Std': bwd_iat_std,
            'SYN Flag Count': data['syn_count'],
            'ACK Flag Count': data['ack_count']
        }])[FEATURE_COLUMNS]  # enforce exact training column order

        start_inference = time.time()

        if model_type == 'svm' and scaler is not None:
            fv = scaler.transform(feature_vector)
            prediction, confidence = get_malicious_confidence(model, fv)
        else:
            prediction, confidence = get_malicious_confidence(model, feature_vector)

        inference_latency = (time.time() - start_inference) * 1000

        # --- TEMPORARY DEBUG: always print confidence + features, even
        # below threshold, to diagnose why live detection isn't firing.
        # Remove this block once detection is confirmed working.
        print(f"[DEBUG] IP={ip} pred={prediction} confidence={confidence:.4f} "
              f"features={feature_vector.iloc[0].to_dict()}")

        if prediction == 1 and confidence >= CONFIDENCE_THRESHOLD:
            IP_STRIKES[ip] = IP_STRIKES.get(ip, 0) + 1
            print(f"\n[!] Suspicious window: IP {ip} | confidence={confidence:.2f} "
                  f"| strikes={IP_STRIKES[ip]}/{STRIKES_REQUIRED} "
                  f"| inference latency={inference_latency:.2f} ms")

            if IP_STRIKES[ip] >= STRIKES_REQUIRED:
                trigger_iptables_mitigation(ip, confidence, feature_vector.iloc[0].to_dict())
        else:
            if ip in IP_STRIKES:
                IP_STRIKES[ip] = 0


def start_live_daemon(interface, target_port, window_size, model_type):
    model, scaler = load_security_artifacts(model_type)

    print(f"\n[+] Starting Live Network Security Daemon on interface '{interface}' (Port {target_port})...")
    print(f"[+] Monitoring in rolling {window_size}-second windows using model: {model_type.upper()}")
    print(f"[+] Mitigation policy: {STRIKES_REQUIRED} consecutive malicious windows "
          f"@ confidence>={CONFIDENCE_THRESHOLD}, auto-unblock after {BLOCK_DURATION_SECONDS}s")
    print("[+] Press Ctrl+C to stop.\n")

    try:
        while True:
            capture = pyshark.LiveCapture(interface=interface, bpf_filter=f'tcp port {target_port}')
            packets_in_window = []
            window_start = time.time()

            for pkt in capture.sniff_continuously():
                packets_in_window.append(pkt)
                if time.time() - window_start >= window_size:
                    break

            print(f"[*] Window closed. Analyzed {len(packets_in_window)} packets across {window_size}s.")
            process_live_window(packets_in_window, model, scaler, model_type)
            capture.close()

    except KeyboardInterrupt:
        print("\n[-] Daemon stopped by user. Cleaning up...")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] WARNING: This script requires root/sudo permissions!")
        print("[!] Run with: sudo ./venv/bin/python live_daemon.py")
    else:
        start_live_daemon(INTERFACE, TARGET_PORT, WINDOW_SIZE, MODEL_CHOICE)