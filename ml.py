from scapy.all import sniff
from collections import deque
import time
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import matplotlib.pyplot as plt
import threading


TRAFFIC_MONITOR_INTERVAL = 1
SPIKE_THRESHOLD = 10_000  

traffic_data = deque(maxlen=60) 
start_time = time.time()

root = tk.Tk()
root.title("Advance threat detection")
root.geometry("800x600")

frame = tk.Frame(root)
frame.pack(pady=10)

log_box = ScrolledText(frame, width=80, height=20)
log_box.pack()

def log_message(message):
    log_box.insert(tk.END, f"{message}\n")
    log_box.see(tk.END)

def process_packet(packet):
    global start_time

    packet_size = len(packet)
    elapsed_time = time.time() - start_time
    traffic_data.append(packet_size)

    if elapsed_time >= TRAFFIC_MONITOR_INTERVAL:
        total_bytes = sum(traffic_data)
        traffic_rate = total_bytes / elapsed_time  

    
        if traffic_rate > SPIKE_THRESHOLD:
            log_message(f"Traffic spike detected: {traffic_rate:.2f} bytes/sec")
        else:
            log_message(f"Normal traffic: {traffic_rate:.2f} bytes/sec")

        start_time = time.time()
        traffic_data.clear()

def start_sniffing():
    log_message("Starting packet capture on TCP port 80 and 443...")
    sniff(filter="tcp port 80 or tcp port 443", prn=process_packet, store=False)

def start_sniffing_thread():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
btn_start = tk.Button(frame, text="Start Monitoring", command=start_sniffing_thread)
btn_start.pack()
def plot_traffic():
    if len(traffic_data) == 0:
        log_message("No traffic data to plot.")
        return

    plt.plot(list(traffic_data), label="Traffic Volume")
    plt.axhline(SPIKE_THRESHOLD, color="red", linestyle="--", label="Spike Threshold")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Traffic (bytes/sec)")
    plt.title("Network Traffic Monitoring")
    plt.legend()
    plt.show()

btn_plot = tk.Button(frame, text="Plot Traffic", command=plot_traffic)
btn_plot.pack()
root.mainloop()
