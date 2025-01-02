import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext
import threading
import time

traffic_data = []
time_data = []
buffer_size = 100  
sniffing = False
SPIKE_THRESHOLD = 1000  

class RealTimeNIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Intrusion Detection System")
        self.root.geometry("800x600")
        self.create_widgets()

        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.plot_frame)
        self.plot_widget = self.canvas.get_tk_widget()
        self.plot_widget.pack()

    def create_widgets(self):
        control_frame = tk.Frame(self.root)
        control_frame.pack(side=tk.TOP, fill=tk.X, pady=10)

        self.start_btn = tk.Button(control_frame, text="Start Monitoring", command=self.start_sniffing, bg="green", fg="white")
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = tk.Button(control_frame, text="Stop Monitoring", command=self.stop_sniffing, bg="red", fg="white", state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        tk.Label(control_frame, text=f"Spike Threshold: {SPIKE_THRESHOLD} bytes", font=("Arial", 12)).pack(side=tk.RIGHT, padx=20)

        self.plot_frame = tk.Frame(self.root)
        self.plot_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=10)
        self.log_text.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    def start_sniffing(self):
        global sniffing
        sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        global sniffing
        sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False, stop_filter=self.stop_filter)

    def stop_filter(self, packet):
        return not sniffing

    def process_packet(self, packet):
        global traffic_data, time_data
        try:
            packet_size = len(packet)
            current_time = time.time()

            
            traffic_data.append(packet_size)
            time_data.append(current_time)

            if len(traffic_data) > buffer_size:
                traffic_data.pop(0)
                time_data.pop(0)

        
            if packet_size > SPIKE_THRESHOLD:
                self.log_text.insert(tk.END, f"Spike detected! Packet size: {packet_size} bytes\n")
                self.log_text.see(tk.END)

            self.update_plot()
        except Exception as e:
            print(f"Error processing packet: {e}")

    def update_plot(self):
        if len(traffic_data) > 1:
            self.ax.clear()
            self.ax.plot(time_data, traffic_data, label="Packet Size")
            self.ax.axhline(SPIKE_THRESHOLD, color='red', linestyle='--', label="Spike Threshold")
            self.ax.set_title("Real-Time Network Traffic")
            self.ax.set_xlabel("Time")
            self.ax.set_ylabel("Packet Size (bytes)")
            self.ax.legend(loc="upper right")
            self.ax.grid()
            self.canvas.draw()


def main():
    root = tk.Tk()
    app = RealTimeNIDSApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
