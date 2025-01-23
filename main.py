import customtkinter as ctk
from sniffing_session import SniffingSession
import customtkinter as ctk
from scapy.all import sniff,get_if_list, get_if_addr
import threading
from collections import Counter
import time
from utils import get_protocol_name
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from tkinter import ttk
import datetime


class PacketSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Multi-Session Packet Sniffer")
        self.geometry("1200x800")

        # Tab control for managing sessions
        self.tab_control = ctk.CTkTabview(self)
        self.tab_control.pack(fill="both", expand=True)

        # Theme and appearance settings
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Manually track tab names
        self.tab_names = []
        self.sessions_data = {}  # Store data for each session

        # ✨ Add risk counter labels at the bottom
        self.risk_counter_frame = ctk.CTkFrame(self)
        self.risk_counter_frame.pack(fill="x", padx=10, pady=5)

        self.risk_labels = {
            "low": ctk.CTkLabel(self.risk_counter_frame, text="Low: 0", fg_color="#edf0e9", text_color="black", corner_radius=8),
            "medium": ctk.CTkLabel(self.risk_counter_frame, text="Medium: 0", fg_color="#daf5a4", text_color="black", corner_radius=8),
            "high": ctk.CTkLabel(self.risk_counter_frame, text="High: 0", fg_color="#FFE4B2", text_color="black", corner_radius=8),
            "critical": ctk.CTkLabel(self.risk_counter_frame, text="Critical: 0", fg_color="#111354", text_color="white", corner_radius=8),
        }

        self.risk_counters = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        for label in self.risk_labels.values():
            label.pack(side="left", padx=10)
            label.bind("<Button-1>", self.filter_by_risk_level)

        # Add the first session by default
        self.add_new_session()

        # Add session control buttons
        control_frame = ctk.CTkFrame(self)
        control_frame.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(control_frame, text="New Session", command=self.add_new_session).pack(side="left", padx=5)
        ctk.CTkButton(control_frame, text="Close Current Tab", command=self.close_current_tab).pack(side="left", padx=5)
        ctk.CTkButton(control_frame, text="Comparison", command=self.open_comparison_window).pack(side="right", padx=5)
        ctk.CTkButton(control_frame, text="Traffic Monitor", command=self.open_traffic_monitor).pack(side="right", padx=5)
        ctk.CTkButton(control_frame, text="Detect Anomalies", command=self.detect_anomalies_for_active_session).pack(side="left", padx=5)
        ctk.CTkButton(control_frame, text="Generate Summary", command=self.generate_summary_for_active_session).pack(side="left", padx=5)

    def add_new_session(self):
        used_numbers = {int(name.split(" ")[1]) for name in self.tab_names}
        session_number = 1
        while session_number in used_numbers:
            session_number += 1

        session_name = f"Session {session_number}"
        session_frame = self.tab_control.add(session_name)
        session = SniffingSession(session_frame,self.risk_labels)
        session.setup_ui()  # Set up the UI
        self.tab_names.append(session_name)  # Track tab names
        self.sessions_data[session_name] = session  # Store the session
    
    def close_current_tab(self):
        """Close the currently selected tab."""
        current_tab = self.tab_control.get()  # Get the name of the selected tab
        if len(self.tab_names) > 1:  # Ensure at least one tab remains
            self.tab_control.delete(current_tab)  # Delete the current tab
            self.tab_names.remove(current_tab)  # Remove from the list
        else:
            from tkinter import messagebox
            messagebox.showwarning("Error", "At least one tab must remain open.")


    def detect_anomalies_for_active_session(self):
        """Trigger anomaly detection for the currently active session."""
        current_tab_name = self.tab_control.get()  # Get the currently selected tab name
        if current_tab_name not in self.sessions_data:
            from tkinter import messagebox
            messagebox.showerror("Error", "No active session found to detect anomalies.")
            return

        session = self.sessions_data[current_tab_name]
        anomalies = session.detect_traffic_anomalies()
        if anomalies:
            session.display_anomalies(anomalies)
        else:
            from tkinter import messagebox
            messagebox.showinfo("No Anomalies", "No anomalies detected in the current session.")


    def generate_summary_for_active_session(self):
        """Trigger summary generation for the currently active session."""
        current_tab_name = self.tab_control.get()  # Get the currently selected tab name
        if current_tab_name not in self.sessions_data:
            from tkinter import messagebox
            messagebox.showerror("Error", "No active session found to generate summary.")
            return

        session = self.sessions_data[current_tab_name]
        session.generate_summary()

    def filter_by_risk_level(self, event):
        """Filter packets based on the selected risk level."""
        try:
            # Get the risk level from the clicked label
            widget_text = event.widget.cget("text")  # Ensure this works for your widget
            label_text = widget_text.split(":")[0].strip().lower()

            for session_name, session in self.sessions_data.items():
                # Clear the table before displaying filtered packets
                session.packet_table.delete(*session.packet_table.get_children())

                # Filter packets by risk level
                session.filtered_packets = [
                    pkt for pkt in session.captured_packets
                    if pkt["risk_level"] == label_text  # Compare the risk level directly
                ]

                # Re-display the filtered packets using the stored metadata
                for packet in session.filtered_packets:
                    risk_level = packet["risk_level"]  # Use stored risk level
                    length = packet["length"]
                    proto_name = packet["proto_name"]

                    # Get colors based on the stored risk level
                    _, bg_color, text_color = session.analyze_packet_risk(length, proto_name)

                    # Insert the packet into the table
                    session.packet_table.insert(
                        "",
                        "end",
                        values=(
                            packet["timestamp"],
                            packet["src_display"],
                            packet["dst_display"],
                            proto_name,
                            length,
                        ),
                        tags=(risk_level,),
                    )

                    # Configure row tag for the risk level
                    session.packet_table.tag_configure(risk_level, background=bg_color, foreground=text_color)

                # Update counters and labels
                session.update_risk_counters()

        except Exception as e:
            print(f"Error in filtering by risk level: {e}")

    def get_risk_colors(self, risk_level):
        """Return background and text colors based on risk level."""
        colors = {
            "critical": ("#111354", "#de4949"),
            "high": ("#FFE4B2", "#804000"),
            "medium": ("#daf5a4", "#666600"),
            "low": ("#edf0e9", "#055af7"),
        }
        return colors.get(risk_level, ("#ffffff", "#000000"))  # Default to white background, black text

    def open_comparison_window(self):
        
        comparison_window = ctk.CTkToplevel(self)
        comparison_window.title("Session Comparison")
        comparison_window.geometry("1200x800")

        # Create matplotlib figures for the graphs
        fig1 = Figure(figsize=(5, 4), dpi=100)
        ax1 = fig1.add_subplot(111)
        ax1.set_title("Length of Packet per Number of Packets")
        ax1.set_xlabel("Packet Number")
        ax1.set_ylabel("Packet Length")

        fig2 = Figure(figsize=(5, 4), dpi=100)
        ax2 = fig2.add_subplot(111)
        ax2.set_title("Number of Packets per Protocol")
        ax2.set_xlabel("Protocol")
        ax2.set_ylabel("Number of Packets")

        # Canvas for the graphs
        canvas1 = FigureCanvasTkAgg(fig1, master=comparison_window)
        canvas1.get_tk_widget().pack(side=ctk.LEFT, fill=ctk.BOTH, expand=True)

        canvas2 = FigureCanvasTkAgg(fig2, master=comparison_window)
        canvas2.get_tk_widget().pack(side=ctk.LEFT, fill=ctk.BOTH, expand=True)

        # Control frame for buttons under the graphs
        button_frame = ctk.CTkFrame(comparison_window)
        button_frame.pack(fill="x", pady=10)

        # Checkbox frame for session selection
        checkbox_frame = ctk.CTkFrame(button_frame)
        checkbox_frame.pack(pady=10)  # Add spacing

        # Add checkboxes for each session
        self.session_checkboxes = {}
        for session in self.tab_names:
            var = ctk.BooleanVar()
            self.session_checkboxes[session] = var
            ctk.CTkCheckBox(checkbox_frame, text=session, variable=var).pack(anchor="w", padx=5)  # Left-aligned checkboxes

        # Add Start Comparison button
        start_button_frame = ctk.CTkFrame(button_frame)
        start_button_frame.pack(pady=10)  # Add spacing

        ctk.CTkButton(
            start_button_frame,
            text="Start Comparison",
            command=lambda: self.start_comparison(ax1, ax2, canvas1, canvas2)
        ).pack()

        self.selected_sessions = []


    def start_comparison(self, ax1, ax2, canvas1, canvas2):
        self.selected_sessions = [session for session, var in self.session_checkboxes.items() if var.get()]
        if len(self.selected_sessions) < 2:
            from tkinter import messagebox
            messagebox.showerror("Error", "Please select at least two sessions before starting the comparison.")
            return

        # Clear previous plots
        ax1.clear()
        ax2.clear()

        colors = ["red", "blue", "green", "purple", "orange"]  # Add more colors if needed

        # Plot Graph 1: Packet length per number of packets
        for idx, session_name in enumerate(self.selected_sessions):
            session = self.sessions_data[session_name]
            lengths = [pkt["length"] for pkt in session.captured_packets]  # Use stored length
            ax1.plot(range(1, len(lengths) + 1), lengths, label=session_name, color=colors[idx % len(colors)])
        ax1.legend()
        ax1.set_title("Length of Packet per Number of Packets")
        ax1.set_xlabel("Packet Number")
        ax1.set_ylabel("Packet Length")

        # Plot Graph 2: Number of packets per protocol
        protocol_counts = {}  # {protocol: [session1_count, session2_count, ...]}
        session_colors = []

        for idx, session_name in enumerate(self.selected_sessions):
            session = self.sessions_data[session_name]
            session_protocols = [
                pkt["proto_name"] for pkt in session.captured_packets if pkt["proto_name"] != "N/A"
            ]
            counts = Counter(session_protocols)

            for protocol, count in counts.items():
                if protocol not in protocol_counts:
                    protocol_counts[protocol] = [0] * len(self.selected_sessions)
                protocol_counts[protocol][idx] = count

            session_colors.append(colors[idx % len(colors)])

        # Plot protocols with different colors per session
        protocol_names = list(protocol_counts.keys())
        x = range(len(protocol_names))
        width = 0.2  # Bar width

        for idx, session_name in enumerate(self.selected_sessions):
            counts = [protocol_counts[protocol][idx] for protocol in protocol_names]
            ax2.bar(
                [p + idx * width for p in x],
                counts,
                width=width,
                label=session_name,
                color=colors[idx % len(colors)],
            )

        # Set x-axis with protocol names
        ax2.set_xticks([p + (width * (len(self.selected_sessions) - 1) / 2) for p in x])
        ax2.set_xticklabels(protocol_names)
        ax2.legend()
        ax2.set_title("Number of Packets per Protocol")
        ax2.set_xlabel("Protocol")
        ax2.set_ylabel("Number of Packets")

        # Redraw the canvases
        canvas1.draw()
        canvas2.draw()

    def open_traffic_monitor(self):
        monitor_window = ctk.CTkToplevel(self)
        monitor_window.title("Traffic Monitor")
        monitor_window.geometry("800x600")

        def available_interfaces():
            """Fetch interfaces with IP addresses for display, similar to get_available_interfaces()."""
            try:
                interfaces = get_if_list()
                readable_interfaces = {}

                for interface in interfaces:
                    try:
                        ip_address = get_if_addr(interface)
                        if ip_address and ip_address != "0.0.0.0":
                            readable_interfaces[interface] = ip_address
                    except Exception:
                        continue

                return readable_interfaces if readable_interfaces else {"No Valid IP Addresses Found": None}

            except Exception as e:
                print(f"Error fetching interfaces: {e}")
                return {"No Interfaces Found": None}

        # Define a function to map IP ranges to user-friendly names
        def get_ip_label(ip_address):
            if ip_address.startswith("192.168"):
                return "WiFi/Local Network"
            elif ip_address.startswith("127.0.0.1"):
                return "Loopback"
            elif ip_address.startswith("169.254"):
                return "Link-Local"
            elif ip_address.startswith("10."):
                return "Private Network"
            else:
                return "Public Network"

        # Fetch interfaces and IPs
        monitor_data = {}
        readable_interfaces = available_interfaces()

        # Create UI elements for each interface
        for interface, ip_address in readable_interfaces.items():
            frame = ctk.CTkFrame(monitor_window)
            frame.pack(fill="x", padx=10, pady=5)

            # Get the user-friendly label
            ip_label = get_ip_label(ip_address)
            display_name = f"{ip_address} ({ip_label})"

            label = ctk.CTkLabel(frame, text=f"IP: {display_name}")
            label.pack(side="left", padx=10)

            traffic_label = ctk.CTkLabel(frame, text="Traffic: 0 packets/s")
            traffic_label.pack(side="right", padx=10)

            monitor_data[interface] = {"packets": 0, "label": traffic_label}

        def monitor_traffic():
            """Monitor and update traffic statistics."""
            while True:
                for interface, data in monitor_data.items():
                    packets = data["packets"]
                    data["label"].configure(text=f"Traffic: {packets} packets/s")
                    data["packets"] = 0  # Reset count for the next interval
                time.sleep(1)

        def packet_handler(packet):
            """Handle each packet and update the corresponding interface's traffic count."""
            if packet.sniffed_on in monitor_data:
                monitor_data[packet.sniffed_on]["packets"] += 1

        # Start monitoring in a separate thread
        threading.Thread(target=monitor_traffic, daemon=True).start()

        # Start sniffing packets on the correct interfaces
        threading.Thread(
            target=lambda: sniff(iface=list(monitor_data.keys()), prn=packet_handler, store=False),
            daemon=True
        ).start()

        


if __name__ == "__main__":
    app = PacketSnifferApp()
    app.mainloop()
