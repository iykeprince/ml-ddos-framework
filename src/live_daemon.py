import time
import os
import subprocess
import joblib
import numpy as np
import pandas as pd
import pyshark

# --- CONFIGURATION ---
INTERFACE = 'eth0'             # Replace with your Victim VM network interface (e.g., eth0, wlan0, enp0s3)
TARGET_PORT = 80               # HTTP Port to monitor
WINDOW_SIZE = 10               # Rolling window in seconds
MODEL_CHOICE = 'random_forest' # Options: 'random_forest' or 'svm'

# Blocked IP cache to prevent duplicate iptables rules
BLOCKED_IPS = set()

def load_security_artifacts(model_type):
    """Loads the serialized model and optional scaler based on user selection."""
    print(f"[+] Loading {model_type.upper()} security artifacts...")
    
    if model_type == 'random_forest':
        model_path = '../models/random_forest.pkl'
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Missing model file at {model_path}. Run 02_train_rf_model.py first!")
        model = joblib.load(model_path)
        scaler = None
    elif model_type == 'svm':
        model_path = '../models/svm_model.pkl'
        scaler_path = '../models/svm_scaler.pkl'
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            raise FileNotFoundError("Missing SVM model or scaler file! Run 03_train_svm_model.py first!")
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
    else:
        raise ValueError("Invalid model choice! Choose 'random_forest' or 'svm'.")
        
    print(f"[+] {model_type.upper()} model successfully loaded into memory.")
    return model, scaler

def trigger_iptables_mitigation(ip_address):
    """Executes system-level shell commands to append an iptables DROP rule for the attacker IP."""
    if ip_address in BLOCKED_IPS:
        return
        
    start_time = time.time()
    cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    
    try:
        # Execute shell command to alter Linux firewall rules
        subprocess.run(cmd, shell=True, check=True)
        mitigation_latency = (time.time() - start_time) * 1000 # Convert to milliseconds
        
        BLOCKED_IPS.add(ip_address)
        print(f"\n[!!!] ALERT: ATTACK DETECTED FROM {ip_address}")
        print(f"[--->] MITIGATION EXECUTION: Appended iptables DROP rule for {ip_address}")
        print(f"[--->] SUBPROCESS EXECUTION LATENCY: {mitigation_latency:.2f} ms\n")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to execute iptables command: {e}")

def process_live_window(packets, model, scaler, model_type):
    """Extracts features from live packets captured in the 10-second window and performs inference."""
    if not packets:
        return

    # Structure window data by Source IP
    flow_data = {}
    
    for pkt in packets:
        try:
            src_ip = pkt.ip.src
            pkt_time = float(pkt.sniff_timestamp)
            has_psh = 1 if hasattr(pkt.tcp, 'flags_push') and pkt.tcp.flags_push == '1' else 0
            
            if src_ip not in flow_data:
                flow_data[src_ip] = {
                    'timestamps': [pkt_time],
                    'psh_flags': [has_psh],
                    'fwd_pkts': 1,
                    'bwd_pkts': 0 # Simplified single-interface live estimation
                }
            else:
                flow_data[src_ip]['timestamps'].append(pkt_time)
                flow_data[src_ip]['psh_flags'].append(has_psh)
                flow_data[src_ip]['fwd_pkts'] += 1
        except AttributeError:
            # Skip non-IP or non-TCP control packets
            continue

    # Perform Feature Extraction & Inference per Source IP in the current window
    for ip, data in flow_data.items():
        if ip in BLOCKED_IPS:
            continue
            
        timestamps = data['timestamps']
        if len(timestamps) < 2:
            continue # Need at least 2 packets to calculate Inter-Arrival Time (IAT)
            
        # Calculate temporal metrics matching training feature schema
        flow_duration = (timestamps[-1] - timestamps[0]) * 1000 # in ms
        iats = np.diff(timestamps) * 1000 # in ms
        fwd_iat_mean = np.mean(iats) if len(iats) > 0 else 0
        bwd_iat_mean = 0 # Baseline assumption for incoming traffic stream
        fwd_psh_flags = sum(data['psh_flags'])
        fwd_pkts_per_sec = data['fwd_pkts'] / WINDOW_SIZE if WINDOW_SIZE > 0 else 0
        bwd_pkts_per_sec = 0
        
        # Build feature vector matching training schema
        feature_vector = pd.DataFrame([{
            'Flow Duration': flow_duration,
            'Fwd IAT Mean': fwd_iat_mean,
            'Bwd IAT Mean': bwd_iat_mean,
            'Fwd PSH Flags': fwd_psh_flags,
            'Fwd Packets/s': fwd_pkts_per_sec,
            'Bwd Packets/s': bwd_pkts_per_sec
        }])
        
        # Inference Execution
        start_inference = time.time()
        
        if model_type == 'svm' and scaler is not None:
            feature_vector_scaled = scaler.transform(feature_vector)
            prediction = model.predict(feature_vector_scaled)[0]
        else:
            prediction = model.predict(feature_vector)[0]
            
        inference_latency = (time.time() - start_inference) * 1000 # in ms
        
        # Output decision
        if prediction == 1:
            print(f"[!] Threat Flagged: IP {ip} | Inference Latency: {inference_latency:.2f} ms")
            trigger_iptables_mitigation(ip)

def start_live_daemon(interface, target_port, window_size, model_type):
    """Main loop: Sniffs traffic continuously in rolling windows."""
    model, scaler = load_security_artifacts(model_type)
    
    print(f"\n[+] Starting Live Network Security Daemon on interface '{interface}' (Port {target_port})...")
    print(f"[+] Monitoring in rolling {window_size}-second windows using model: {model_type.upper()}")
    print("[+] Press Ctrl+C to stop.\n")
    
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=f'tcp port {target_port}')
    
    try:
        while True:
            window_start = time.time()
            packets_in_window = []
            
            # Sniff packets for the duration of the rolling window
            capture.sniff(timeout=window_size)
            
            for pkt in capture:
                packets_in_window.append(pkt)
                
            print(f"[*] Window closed. Analyzed {len(packets_in_window)} packets across {window_size}s.")
            process_live_window(packets_in_window, model, scaler, model_type)
            
    except KeyboardInterrupt:
        print("\n[-] Daemon stopped by user. Cleaning up...")
    finally:
        capture.close()

if __name__ == "__main__":
    # Ensure script is executed with root/sudo privileges to manipulate iptables
    if os.geteuid() != 0:
        print("[!] WARNING: This script requires root/sudo permissions to update iptables firewall rules!")
        print("[!] Run with: sudo ../venv/bin/python 04_live_daemon.py")
    else:
        start_live_daemon(INTERFACE, TARGET_PORT, WINDOW_SIZE, MODEL_CHOICE)