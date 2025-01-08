import customtkinter as ctk
from tkinter import ttk
from scapy.all import sniff, wrpcap, rdpcap, conf, get_if_list, get_if_addr
import threading
import datetime
from collections import Counter
from decimal import Decimal
import time
from cryptography.fernet import Fernet
import os
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random




def start_live_traffic(parent, risk_labels, counters):
    def update_graph():
        nonlocal capturing
        x_data = []
        y_data = []
        counter_levels = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        # Check if a graph window already exists
        if hasattr(parent, 'log_window') and parent.log_window is not None:
            parent.log_window.destroy()

        # Create a new window for live traffic
        parent.log_window = ctk.CTkToplevel(parent)
        parent.log_window.title("Live Data Traffic")
        parent.log_window.geometry("1200x800")
        
        # Create the figure and axes here
        fig = Figure(figsize=(8, 6), dpi=100)
        graph_axes = fig.add_subplot(111)  # Explicitly create axes
        
        # Embed the Matplotlib figure in the Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=parent.log_window)
        canvas.get_tk_widget().pack(side=ctk.TOP, fill=ctk.BOTH, expand=True)
        
        while capturing:
            traffic_rate = random.randint(100, 2000)  # Simulate traffic data
            x_data.append(len(x_data) + 1)
            y_data.append(traffic_rate)

            # Update graph
            graph_axes.clear()
            graph_axes.plot(x_data, y_data, label="Traffic Rate")
            graph_axes.set_title("Live Data Traffic")
            graph_axes.set_xlabel("Time (s)")
            graph_axes.set_ylabel("Rate (bytes/sec)")
            graph_axes.legend()

            # Update risk levels
            if traffic_rate < 500:
                counter_levels["low"] += 1
            elif traffic_rate < 1000:
                counter_levels["medium"] += 1
            elif traffic_rate < 1500:
                counter_levels["high"] += 1
            else:
                counter_levels["critical"] += 1

            # Update risk counters
            for level, label in risk_labels.items():
                label.configure(text=f"{level.capitalize()}: {counter_levels[level]}")

            counters["low"], counters["medium"], counters["high"], counters["critical"] = counter_levels.values()

            # Redraw canvas
            canvas.draw()

            time.sleep(1)  # Update every second

    # Ensure only one thread runs for live traffic
    if not hasattr(parent, 'traffic_thread') or not parent.traffic_thread.is_alive():
        capturing = True
        parent.traffic_thread = threading.Thread(target=update_graph, daemon=True)
        parent.traffic_thread.start()




    