import customtkinter as ctk
from tkinter import ttk
from scapy.all import sniff, wrpcap, rdpcap, conf, get_if_list, get_if_addr
import threading
import datetime
from collections import Counter
from cryptography.fernet import Fernet
from decimal import Decimal
import os
import time
import matplotlib.pyplot as plt
from utils import get_protocol_name
from collections import deque
import json
from PIL import Image
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.backend_bases import MouseEvent
import numpy as np




class SniffingSession:
    def __init__(self, frame,risk_labels):
        self.frame = frame
        self.captured_packets = []
        self.packet_counts = Counter()
        self.total_bytes = 0
        self.start_time = None
        self.is_running = False
        self.promiscuous_mode = ctk.BooleanVar(value=True)
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.scrollable_frame = None  # Added for scrollable table reference
        self.throughput_history = deque(maxlen=5)
        self.risk_labels = risk_labels  # Risk counters
        self.risk_counters = {"low": 0, "medium": 0, "high": 0, "critical": 0}


    def start_capture(self):
        """Start packet capturing."""
        selected_ip = self.interface_var.get()
        manual_ip = self.manual_interface_var.get().strip()

        #  # Reset risk counters for the new session
        # self.risk_counters = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        # self.update_risk_counters()
        # self.captured_packets.clear()
        # self.total_bytes = 0

        # Prefer manual IP if provided
        if manual_ip:
            selected_interface = self.interface_mapping.get(manual_ip, None) 
            if not selected_interface:
                # Attempt to directly use the manual IP with a default mapping
                try:
                    selected_interface = next(
                        iface for iface, ip in self.interface_mapping.items() if ip == manual_ip
                    )
                except StopIteration:
                    self.status_label.configure(text="Error: Manual IP does not match any known interface.")
                    return
        else:
            selected_interface = self.interface_mapping.get(selected_ip, None)

        if not selected_interface:
            self.status_label.configure(text="Error: Please select or type a valid network interface IP.")
            return

        # Capture configuration
        filter_parts = []
        if self.src_ip_var.get():
            filter_parts.append(f"src host {self.src_ip_var.get()}")
        if self.dst_ip_var.get():
            filter_parts.append(f"dst host {self.dst_ip_var.get()}")
        if self.src_port_var.get():
            filter_parts.append(f"src port {self.src_port_var.get()}")
        if self.dst_port_var.get():
            filter_parts.append(f"dst port {self.dst_port_var.get()}")
        if self.protocol_var.get():
            filter_parts.append(self.protocol_var.get().lower())
        if self.custom_filter_var.get():
            filter_parts.append(self.custom_filter_var.get())

        capture_filter = " and ".join(filter_parts)
        packet_count = int(self.packet_count_var.get())
        conf.sniff_promisc = self.promiscuous_mode.get()

        self.status_label.configure(text="Status: Capturing...")
        self.is_running = True
        self.start_time = datetime.datetime.now()

        # Wrapper to ensure correct counting
        self.processed_packet_count = 0

        def packet_handler(packet):
            self.process_packet(packet)

        def capture():
            try:
                sniff(
                    iface=selected_interface,
                    filter=capture_filter,
                    count=packet_count,
                    prn=self.process_packet,
                    stop_filter=lambda x: not self.is_running,
                )
                self.status_label.configure(text="Status: Capture Complete")
                self.is_running = False
            except Exception as e:
                self.status_label.configure(text=f"Error: {e}")

        threading.Thread(target=capture, daemon=True).start()
        threading.Thread(target=self.update_live_stats, daemon=True).start()

    def update_live_stats(self):
        """Update live statistics for throughput and utilization."""
        while self.is_running or self.captured_packets:
            elapsed_time = (datetime.datetime.now() - self.start_time).total_seconds()
            elapsed_time = max(elapsed_time, 1)  # Avoid division by zero
            
            max_bandwidth = float(self.max_bandwidth_var.get() or 1e6)  # Default to 1 Mbps
            throughput_bps = (self.total_bytes * 8) / elapsed_time  # Convert bytes to bits/sec
            
            # Add current throughput to history and calculate the moving average
            self.throughput_history.append(throughput_bps)
            avg_throughput_bps = sum(self.throughput_history) / len(self.throughput_history)
            
            utilization = (avg_throughput_bps / max_bandwidth) * 100 if max_bandwidth > 0 else 0

            self.stats_label.configure(
                text=f"Total Packets: {len(self.captured_packets)}\n"
                    f"Throughput: {int(avg_throughput_bps)} bps\n"
                    f"Utilization: {utilization:.2f}%"
            )

            time.sleep(1)



    def stop_capture(self):
        """Stop packet capturing."""
        self.is_running = False
        self.status_label.configure(text="Status: Capture Stopped")

    def process_packet(self, packet,update_risk=True):
        """Process and display a captured packet with risk-level coloring and protocol detection."""
        try:
            # Extract timestamp
            timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S') if hasattr(packet, 'time') else "N/A"

            # Extract MAC addresses
            src_mac = getattr(packet, 'src', "N/A")
            dst_mac = getattr(packet, 'dst', "N/A")

            # Extract IP layer details
            src_ip, dst_ip, proto_name = "N/A", "N/A", "N/A"
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                proto_name = get_protocol_name(packet["IP"].proto)

            # Detect application-layer protocols
            if packet.haslayer("TCP"):
                payload = bytes(packet["TCP"].payload).decode(errors="ignore").lower()
                if "http" in payload:
                    proto_name = "HTTP"
                elif "ftp" in payload:
                    proto_name = "FTP"
                elif "ssh" in payload:
                    proto_name = "SSH"
                elif "tls" in payload or "ssl" in payload:
                    proto_name = "TLS/SSL"
            elif packet.haslayer("UDP"):
                if packet.haslayer("DNS"):
                    proto_name = "DNS"

            # Display strings
            src_display = f"{src_mac} | {src_ip}"
            dst_display = f"{dst_mac} | {dst_ip}"
            length = len(packet)

            # Generate a unique identifier for the packet
            packet_id = f"{timestamp}-{src_display}-{dst_display}-{length}"

            # Check if the packet is already processed
            if any(p['id'] == packet_id for p in self.captured_packets):
                return  # Skip duplicate packets

            # Append the packet for storage with metadata
            self.captured_packets.append({
                "id": packet_id,  # Unique identifier
                "packet": packet,  # Store the full packet
                "timestamp": timestamp,
                "src_display": src_display,
                "dst_display": dst_display,
                "proto_name": proto_name,
                "length": length,
                "risk_level": None,  # Will be updated below
            })
            self.total_bytes += length

            # Risk analysis
            if update_risk:
                risk_level, bg_color, text_color = self.analyze_packet_risk(length, proto_name)
                self.captured_packets[-1]["risk_level"] = risk_level
                self.risk_counters[risk_level] += 1
            else:
                risk_level, bg_color, text_color = "low", "#edf0e9", "#055af7"

            # Insert packet into the table with proper styling
            self.packet_table.insert(
                "",
                "end",
                values=(timestamp, src_display, dst_display, proto_name, length),
                tags=(risk_level,),
            )
            self.packet_table.tag_configure(risk_level, background=bg_color, foreground=text_color)

            # Update risk counters (UI operation)
            self.update_risk_counters()

        except Exception as e:
            print(f"Error processing packet: {e}")

    def analyze_packet_risk(self, length, proto_name):
        """Analyze the risk level of a packet and return the risk level, background color, and text color."""
        if length > 1500:
            return "critical", "#111354", "#de4949"  # Critical
        elif length > 1000:
            return "high", "#FFE4B2", "#804000"  # High
        elif proto_name in ["ICMP", "UDP"]:
            return "medium", "#daf5a4", "#666600"  # Medium
        else:
            return "low", "#edf0e9", "#055af7"  # Low

    def display_packet(self, packet, update_risk=True):
        """Display a packet in the table with risk-level coloring."""
        try:
            # Extract timestamp
            timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S') if hasattr(packet, 'time') else "N/A"

            # Extract MAC addresses
            src_mac = getattr(packet, 'src', "N/A")
            dst_mac = getattr(packet, 'dst', "N/A")

            # Extract IP details
            src_ip, dst_ip, proto_name = "N/A", "N/A", "N/A"
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                proto_name = get_protocol_name(packet["IP"].proto)

            length = len(packet)

            # Get risk level and colors
            if update_risk:
                risk_level, bg_color, text_color = self.analyze_packet_risk(length, proto_name)
                self.risk_counters[risk_level] += 1
            else:
                risk_level, bg_color, text_color = "low", "#edf0e9", "#055af7"

            # Insert the packet into the table
            self.packet_table.insert(
                "",
                "end",
                values=(timestamp, src_mac + " | " + src_ip, dst_mac + " | " + dst_ip, proto_name, length),
                tags=(risk_level,),
            )

            # Configure row tag with colors
            self.packet_table.tag_configure(risk_level, background=bg_color, foreground=text_color)

            # Update risk counters in the UI
            self.update_risk_counters()

        except Exception as e:
            print(f"Error displaying packet: {e}")


    def update_risk_counters(self):
        """Update the risk counters displayed at the bottom of the UI."""
        for level, label in self.risk_labels.items():
            label.configure(text=f"{level.capitalize()}: {self.risk_counters.get(level, 0)}")

    def show_packet_details(self, event):
        """Display detailed packet information with risk level, explanation, and protocol breakdown."""
        selected_item = self.packet_table.selection()
        if not selected_item:
            return

        packet_index = self.packet_table.index(selected_item)  # Get index of selected packet
        packet_list = getattr(self, "filtered_packets", self.captured_packets)

        if packet_index >= len(self.captured_packets):
            return  # Avoid out-of-range error

        metadata = packet_list[packet_index]
        packet = metadata["packet"]
        risk_level = metadata["risk_level"]

        # Define risk explanations
        risk_explanations = {
            "critical": (
                "Packet size exceeds 1500 bytes, which is unusually large and could indicate a potential attack or data breach.",
                "Inspect the source of this large packet. If it's unexpected, consider blocking the sender.",
                "#FFCCCC", "#660000"
            ),
            "high": (
                "Packet size exceeds 1000 bytes, which may indicate suspicious activity or a large data transfer attempt.",
                "Verify the sender's IP and investigate further. Large packets could be part of a data exfiltration attempt.",
                "#FFE4B2", "#804000"
            ),
            "medium": (
                "This packet uses ICMP or UDP, which are common for diagnostics and streaming, but can be exploited in DDoS attacks.",
                "Monitor for repeated ICMP/UDP packets from the same source to detect possible DDoS attacks.",
                "#FFF5CC", "#666600"
            ),
            "low": (
                "This packet appears normal with no immediate risks detected.",
                "No immediate action required.",
                "#E6FFE6", "#336633"
            ),
        }

        explanation, suggestions, risk_color, text_color = risk_explanations[risk_level]

        # Create a new window for packet details
        details_window = ctk.CTkToplevel(self.frame)
        details_window.title("Packet Details")
        details_window.geometry("800x800")

        # Header
        ctk.CTkLabel(details_window, text="Packet Details", font=("Arial", 16, "bold")).pack(pady=10)

        # Use a Text widget to display packet details
        details_text = ctk.CTkTextbox(details_window, wrap="none")
        details_text.pack(fill="both", expand=True, padx=10, pady=10)

        

        try:
            # Capture packet details using Scapy's show() method
            from io import StringIO
            import sys

            old_stdout = sys.stdout
            sys.stdout = buffer = StringIO()
            packet.show()
            sys.stdout = old_stdout

            packet_details = buffer.getvalue()
        except Exception as e:
            packet_details = f"❗ Error displaying packet details: {e}"

        # Display packet details in the Text widget
        details_text.insert("1.0", packet_details)
        details_text.configure(state="disabled")  # Make it read-only

        # Add a risk level section with color
        risk_frame = ctk.CTkFrame(details_window, fg_color=risk_color)
        risk_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            risk_frame,
            text=f"⚠️ Risk Level: {risk_level.capitalize()}",
            font=("Arial", 14, "bold"),
            text_color=text_color,
        ).pack(pady=5)

        ctk.CTkLabel(
            risk_frame,
            text=f"📋 Explanation: {explanation}",
            font=("Arial", 12),
            text_color=text_color,
            wraplength=750,
        ).pack(pady=5)

        ctk.CTkLabel(
            risk_frame,
            text=f"💡 Suggested Action: {suggestions}",
            font=("Arial", 12),
            text_color=text_color,
            wraplength=750,
        ).pack(pady=5)

        # Add a "Show Flow" button
        ctk.CTkButton(
            details_window,
            text="Show Flow",
            command=lambda: self.visualize_packet_flow(packet)
        ).pack(pady=10)

        

        # Close button
        ctk.CTkButton(details_window, text="Close", command=details_window.destroy).pack(pady=10)

    def visualize_packet_flow(self, packets):
        """Visualize packet flow with hover tooltips displaying detailed information."""
        if not packets:
            ctk.CTkMessageBox.showinfo(
                title="Flow Visualization",
                message="No packets available to visualize flow.",
            )
            return

        # Create the graph
        graph = nx.DiGraph()
        node_details = {}
        edge_details = {}

        # Add nodes and edges for each packet
        for packet in packets:
            if not packet.haslayer("IP"):
                continue

            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            protocol = get_protocol_name(packet["IP"].proto)
            length = len(packet)
            timestamp = packet.time

            # Add nodes with details
            graph.add_node(src_ip)
            graph.add_node(dst_ip)
            node_details[src_ip] = f"Source IP: {src_ip}\nTimestamp: {timestamp}"
            node_details[dst_ip] = f"Destination IP: {dst_ip}\nTimestamp: {timestamp}"

            # Add edges with details
            edge_label = f"{protocol} | {length} bytes"
            graph.add_edge(src_ip, dst_ip, label=edge_label)
            edge_details[(src_ip, dst_ip)] = f"Protocol: {protocol}\nSize: {length} bytes\nTimestamp: {timestamp}"

        # Create the visualization
        fig, ax = plt.subplots(figsize=(10, 8))
        pos = nx.spring_layout(graph)

        nx.draw(
            graph,
            pos,
            with_labels=True,
            node_size=2000,
            node_color="lightblue",
            font_size=10,
            font_weight="bold",
            edge_color="gray",
        )
        nx.draw_networkx_edge_labels(graph, pos, edge_labels=nx.get_edge_attributes(graph, "label"))

        # Tooltip initialization
        annot = ax.annotate(
            "",
            xy=(0, 0),
            xytext=(20, 20),
            textcoords="offset points",
            bbox=dict(boxstyle="round", fc="w"),
            arrowprops=dict(arrowstyle="->"),
        )
        annot.set_visible(False)

        # Update tooltip text and position
        def update_annot(event, hovered_node=None, hovered_edge=None):
            if hovered_node:
                annot.xy = event.xdata, event.ydata
                annot.set_text(node_details[hovered_node])
            elif hovered_edge:
                annot.xy = event.xdata, event.ydata
                annot.set_text(edge_details[hovered_edge])
            annot.set_visible(True)

        # Hide tooltip when not hovering
        def hover(event: MouseEvent):
            if event.inaxes != ax:
                return

            hovered_node = None
            hovered_edge = None

            # Check for node hover
            for node, (x, y) in pos.items():
                if (event.xdata - x) ** 2 + (event.ydata - y) ** 2 < 0.005:  # Adjust radius as needed
                    hovered_node = node
                    break

            # Check for edge hover
            if not hovered_node:
                for edge, (start, end) in nx.get_edge_attributes(graph, "label").items():
                    if abs(event.xdata - pos[edge[0]][0]) < 0.05 and abs(event.ydata - pos[edge[1]][1]) < 0.05:
                        hovered_edge = edge
                        break

            if hovered_node:
                update_annot(event, hovered_node=hovered_node)
            elif hovered_edge:
                update_annot(event, hovered_edge=hovered_edge)
            else:
                annot.set_visible(False)

            fig.canvas.draw_idle()

        # Connect hover event to the function
        fig.canvas.mpl_connect("motion_notify_event", hover)

        plt.title("Packet Flow Visualization with Protocol Details on Hover")
        plt.show()

    def get_packet_risk(self, packet):
        """Determine the risk level and explanation of a packet."""
        length = len(packet)
        if length > 1500:
            return "critical", "Packet size exceeds 1500 bytes, which is unusually large and could indicate a potential attack or data breach."
        elif length > 1000:
            return "high", "Packet size exceeds 1000 bytes, which may indicate suspicious activity or a large data transfer attempt."
        elif packet.haslayer("ICMP") or packet.haslayer("UDP"):
            return "medium", "This packet uses ICMP or UDP, which are common for diagnostics and streaming, but can be exploited in DDoS attacks."
        else:
            return "low", "This packet appears normal with no immediate risks detected."
        
        
    def get_packet_details(self, packet):
        """Format and return detailed packet information."""
        details = []

        try:
            details.append("🔹 **General Details:**")
            details.append(f"- Timestamp: {datetime.datetime.fromtimestamp(packet.time) if hasattr(packet, 'time') else 'N/A'}")
            details.append(f"- Length: {len(packet)} bytes")

            # Ethernet Layer
            if packet.haslayer("Ether"):
                details.append("\n🔹 **Ethernet Layer:**")
                details.append(f"- Source MAC: {packet['Ether'].src}")
                details.append(f"- Destination MAC: {packet['Ether'].dst}")
                details.append(f"- Type: {hex(packet['Ether'].type)}")

            # IP Layer
            if packet.haslayer("IP"):
                details.append("\n🔹 **IP Layer:**")
                details.append(f"- Source IP: {packet['IP'].src}")
                details.append(f"- Destination IP: {packet['IP'].dst}")
                details.append(f"- Protocol: {get_protocol_name(packet['IP'].proto)}")
                details.append(f"- TTL: {packet['IP'].ttl}")
                details.append(f"- Header Length: {packet['IP'].ihl}")
                details.append(f"- Fragmentation Flags: {packet['IP'].flags}")

            # TCP Layer
            if packet.haslayer("TCP"):
                details.append("\n🔹 **TCP Layer:**")
                details.append(f"- Source Port: {packet['TCP'].sport}")
                details.append(f"- Destination Port: {packet['TCP'].dport}")
                details.append(f"- Sequence Number: {packet['TCP'].seq}")
                details.append(f"- Acknowledgment Number: {packet['TCP'].ack}")
                details.append(f"- Flags: {packet['TCP'].flags}")
                details.append(f"- Window Size: {packet['TCP'].window}")
                details.append(f"- Checksum: {packet['TCP'].chksum}")

            # UDP Layer
            if packet.haslayer("UDP"):
                details.append("\n🔹 **UDP Layer:**")
                details.append(f"- Source Port: {packet['UDP'].sport}")
                details.append(f"- Destination Port: {packet['UDP'].dport}")
                details.append(f"- Length: {packet['UDP'].len}")
                details.append(f"- Checksum: {packet['UDP'].chksum}")

            # ARP Layer
            if packet.haslayer("ARP"):
                details.append("\n🔹 **ARP Layer:**")
                details.append(f"- Hardware Type: {packet['ARP'].hwtype}")
                details.append(f"- Protocol Type: {hex(packet['ARP'].ptype)}")
                details.append(f"- Hardware Size: {packet['ARP'].hwlen}")
                details.append(f"- Protocol Size: {packet['ARP'].plen}")
                details.append(f"- Operation: {packet['ARP'].op}")
                details.append(f"- Sender MAC: {packet['ARP'].hwsrc}")
                details.append(f"- Sender IP: {packet['ARP'].psrc}")
                details.append(f"- Target MAC: {packet['ARP'].hwdst}")
                details.append(f"- Target IP: {packet['ARP'].pdst}")

            # ICMP Layer
            if packet.haslayer("ICMP"):
                details.append("\n🔹 **ICMP Layer:**")
                details.append(f"- Type: {packet['ICMP'].type}")
                details.append(f"- Code: {packet['ICMP'].code}")
                details.append(f"- Checksum: {packet['ICMP'].chksum}")

            # DNS Layer (if applicable)
            if packet.haslayer("DNS"):
                details.append("\n🔹 **DNS Layer:**")
                details.append(f"- DNS QR: {packet['DNS'].qr}")
                details.append(f"- DNS Opcode: {packet['DNS'].opcode}")
                details.append(f"- DNS Questions: {packet['DNS'].qdcount}")
                details.append(f"- DNS Answers: {packet['DNS'].ancount}")
                details.append(f"- DNS Authority Records: {packet['DNS'].nscount}")
                details.append(f"- DNS Additional Records: {packet['DNS'].arcount}")

            # Raw Layer (Packet Payload)
            if packet.haslayer("Raw"):
                details.append("\n🔹 **Raw Payload:**")
                raw_data = bytes(packet["Raw"].load).decode('utf-8', errors='replace')
                details.append(f"- Data: {raw_data}")

        except Exception as e:
            details.append(f"\n❗ Error reading packet details: {e}")

        return "\n".join(details)

        
    def load_pcap_file(self):
        """Load packets from an external PCAP file."""
        from tkinter.filedialog import askopenfilename

        file_path = askopenfilename(filetypes=[("PCAP files", "*.pcap")])

        if not file_path:
            self.status_label.configure(text="Load operation cancelled.")
            return

        try:
            # Read packets from the file
            loaded_packets = rdpcap(file_path)
            self.display_loaded_packets(loaded_packets)
            self.status_label.configure(
                text=f"Loaded {len(loaded_packets)} packets from {file_path}"
            )
        except Exception as e:
            self.status_label.configure(text=f"Error loading file: {e}")


    def display_loaded_packets(self, packets):
        """Display packets loaded from a PCAP file."""
        for packet in packets:
            try:
                # Extract timestamp
                packet_time = float(packet.time) if isinstance(packet.time, Decimal) else packet.time
                timestamp = datetime.datetime.fromtimestamp(packet_time).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                timestamp = "N/A"

            # Extract MAC addresses
            src_mac = packet.src if hasattr(packet, 'src') else "N/A"
            dst_mac = packet.dst if hasattr(packet, 'dst') else "N/A"

            # Default to N/A for IP information
            src_ip, dst_ip, proto_name = "N/A", "N/A", "N/A"

            # Extract IP layer information if available
            if packet.haslayer("IP"):
                src_ip, dst_ip = packet["IP"].src, packet["IP"].dst
                proto_name = get_protocol_name(packet["IP"].proto)

            src_display = f"{src_mac} | {src_ip}"
            dst_display = f"{dst_mac} | {dst_ip}"
            length = len(packet)

            # Add packet to the table
            self.packet_table.insert("", "end", values=(timestamp, src_display, dst_display, proto_name, length))

            
    def save_packets(self):
        """Save captured packets to file, allowing the user to choose file type via dialog."""
        if not self.captured_packets:
            self.status_label.configure(text="No packets to save.")
            return

        from tkinter.filedialog import asksaveasfilename
        file_path = asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("Encrypted files", "*.enc")],
        )

        if not file_path:
            self.status_label.configure(text="Save operation cancelled.")
            return

        # Determine save type based on file extension
        if file_path.endswith(".pcap"):
            # Save as unencrypted PCAP
            wrpcap(file_path, self.captured_packets)
            self.status_label.configure(text=f"Packets saved to {file_path}")
        elif file_path.endswith(".enc"):
            # Save as encrypted
            from tkinter.simpledialog import askstring
            password = askstring("Encryption Password", "Enter a password to encrypt the file:", show="*")
            if not password:
                self.status_label.configure(text="Encryption cancelled.")
                return

            # Save packets temporarily as a PCAP file
            temp_file = "temp.pcap"
            wrpcap(temp_file, self.captured_packets)

            # Encrypt the file
            with open(temp_file, "rb") as f:
                data = f.read()
                cipher = Fernet(Fernet.generate_key())
                encrypted_data = cipher.encrypt(data)

            os.remove(temp_file)

            with open(file_path, "wb") as f:
                f.write(encrypted_data)

            self.status_label.configure(text=f"Packets encrypted and saved to {file_path}")
        else:
            self.status_label.configure(text="Unsupported file type selected.")

      
    def reset_filters(self):
        """Reset all filter fields to their default values."""
        self.src_ip_var.set("")
        self.dst_ip_var.set("")
        self.src_port_var.set("")
        self.dst_port_var.set("")
        self.protocol_var.set("")
        self.custom_filter_var.set("")


    def toggle_theme(self):
        """Switch between light and dark themes."""
        if self.dark_mode_var.get():  # If dark mode is enabled
            ctk.set_appearance_mode("dark")
            self.packet_table.configure(
                background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b"
            )
        else:  # Switch to light mode
            ctk.set_appearance_mode("light")
            self.packet_table.configure(
                background="white", foreground="black", fieldbackground="white"
            )

    # Geo feture

    '''
    def geo_locate_ips(self):
        
        """Visualize the geographic location of source and destination IPs using GeoIP2 CSV data."""
        if not self.captured_packets:
            self.status_label.configure(text="No packets to geo-locate.")
            return

        try:
            # Paths to the CSV files
            import os
            base_dir = os.path.dirname(os.path.abspath(__file__))
            data_dir = os.path.join(base_dir, "data")
            locations_path = os.path.join(data_dir, "GeoIP2-City-Locations-en.csv")
            blocks_path = os.path.join(data_dir, "GeoIP2-City-Blocks-IPv4.csv")

            # Load GeoIP blocks and location data
            blocks = pd.read_csv(blocks_path)
            locations = pd.read_csv(locations_path)

            # Merge blocks and locations on geoname_id to include latitude and longitude in location data
            merged_data = blocks.merge(locations, on="geoname_id", how="left")

            # Debug: Print merged data columns
            print("Merged Data Columns:", merged_data.columns)

            # Create a map centered on a default location
            map_center = [20.0, 10.0]  # Default map center
            geo_map = folium.Map(location=map_center, zoom_start=2)

            def is_private_ip(ip):
                """Check if an IP address is private."""
                try:
                    return ipaddress.ip_address(ip).is_private
                except ValueError:
                    return False

            for packet in self.captured_packets:
                try:
                    # Extract IPs from src_display and dst_display
                    src_ip = packet["src_display"].split("|")[1].strip()
                    dst_ip = packet["dst_display"].split("|")[1].strip()

                    # Initialize variables for coordinates
                    src_lat = src_lon = dst_lat = dst_lon = None

                    # Process Source IP
                    if src_ip == "N/A" or is_private_ip(src_ip):
                        print(f"Skipping or marking private/invalid Source IP: {src_ip}")
                    else:
                        print(f"Processing Source IP: {src_ip}")
                        src_row = blocks.loc[blocks["network"].apply(
                            lambda net: ipaddress.ip_address(src_ip) in ipaddress.ip_network(net))]
                        if src_row.empty:
                            print(f"No match found for Source IP: {src_ip}. Checking CIDR ranges in dataset...")
                            print(f"All CIDR ranges in the dataset: {blocks['network'].tolist()}")
                        else:
                            src_loc_id = src_row.iloc[0]["geoname_id"]
                            src_location = merged_data.loc[merged_data["geoname_id"] == src_loc_id]
                            if not src_location.empty:
                                src_lat = src_location.iloc[0]["latitude"]
                                src_lon = src_location.iloc[0]["longitude"]

                    # Process Destination IP
                    if dst_ip == "N/A" or is_private_ip(dst_ip):
                        print(f"Skipping or marking private/invalid Destination IP: {dst_ip}")
                    else:
                        print(f"Processing Destination IP: {dst_ip}")
                        dst_row = blocks.loc[blocks["network"].apply(
                            lambda net: ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net))]
                        if dst_row.empty:
                            print(f"No match found for Destination IP: {dst_ip}. Checking CIDR ranges in dataset...")
                            print(f"All CIDR ranges in the dataset: {blocks['network'].tolist()}")
                        else:
                            dst_loc_id = dst_row.iloc[0]["geoname_id"]
                            dst_location = merged_data.loc[merged_data["geoname_id"] == dst_loc_id]
                            if not dst_location.empty:
                                dst_lat = dst_location.iloc[0]["latitude"]
                                dst_lon = dst_location.iloc[0]["longitude"]

                    # Add markers for valid lat/lon
                    if src_lat is not None and src_lon is not None:
                        folium.Marker(
                            location=[src_lat, src_lon],
                            popup=f"Source: {src_ip}",
                            icon=folium.Icon(color="blue", icon="info-sign"),
                        ).add_to(geo_map)

                    if dst_lat is not None and dst_lon is not None:
                        folium.Marker(
                            location=[dst_lat, dst_lon],
                            popup=f"Destination: {dst_ip}",
                            icon=folium.Icon(color="red", icon="info-sign"),
                        ).add_to(geo_map)

                    # Draw a line between source and destination if both are valid
                    if src_lat is not None and src_lon is not None and dst_lat is not None and dst_lon is not None:
                        folium.PolyLine(
                            locations=[[src_lat, src_lon], [dst_lat, dst_lon]],
                            color="green",
                            weight=2.5,
                            opacity=0.8,
                        ).add_to(geo_map)

                except Exception as e:
                    print(f"Error processing packet for geo-location: {e}")

            # Save the map to an HTML file
            output_path = os.path.join(base_dir, "geo_location_map.html")
            geo_map.save(output_path)

            # Open the map in the default browser
            try:
                # Enclose the path in double quotes to handle spaces and special characters
                subprocess.run(f'start "" "{output_path}"', shell=True, check=True)
            except Exception as e:
                print(f"Error opening the map file: {e}")
            self.status_label.configure(text="Geo-location map generated successfully.")

        except Exception as e:
            self.status_label.configure(text=f"Error generating GeoIP data: {e}")
            '''


    def detect_traffic_anomalies(self):
        """Detect and display traffic anomalies in the captured packets."""
        if not self.captured_packets:
            self.status_label.configure(text="No packets to analyze for anomalies.")
            return

        anomalies = []
        threshold = 1000  # Large packet size threshold
        common_protocols = ["TCP", "UDP", "ICMP", "HTTP", "TLS", "DNS"]
        protocol_counts = Counter(packet["proto_name"] for packet in self.captured_packets if packet["proto_name"] != "N/A")

        # Detect large packets and uncommon protocols
        large_packets = [packet for packet in self.captured_packets if packet["length"] > threshold]
        uncommon_protocols = {proto: count for proto, count in protocol_counts.items() if proto not in common_protocols}

        # Detect throughput spikes
        elapsed_time = (datetime.datetime.now() - self.start_time).total_seconds()
        avg_throughput = (self.total_bytes * 8) / elapsed_time if elapsed_time > 0 else 0
        traffic_spike = avg_throughput > 1e6  # Example threshold: 1 Mbps

        # Compile anomalies
        if large_packets:
            anomalies.append(f"Large Packets: {len(large_packets)} detected (Max: {max(p['length'] for p in large_packets)} bytes).")
        if uncommon_protocols:
            anomalies.append(f"Uncommon Protocols: {', '.join([f'{proto} ({count})' for proto, count in uncommon_protocols.items()])}.")
        if traffic_spike:
            anomalies.append(f"Traffic Spike Detected: {avg_throughput:.2f} bps (Threshold: 1 Mbps).")

        # Display results
        if anomalies:
            self.display_anomalies(anomalies, large_packets, protocol_counts, traffic_spike)
        else:
            self.status_label.configure(text="No anomalies detected.")

    def display_anomalies(self, anomalies, large_packets, protocol_counts, traffic_spike):
        """Display detected anomalies in a pop-up window."""
        anomaly_window = ctk.CTkToplevel(self.frame)
        anomaly_window.title("Traffic Anomalies")
        anomaly_window.geometry("600x400")

        ctk.CTkLabel(anomaly_window, text="Detected Anomalies", font=("Arial", 16, "bold")).pack(pady=10)

        anomaly_listbox = ctk.CTkTextbox(anomaly_window)
        anomaly_listbox.pack(fill="both", expand=True, padx=10, pady=10)

        for anomaly in anomalies:
            anomaly_listbox.insert("end", anomaly + "\n")

        # Add buttons for visualizations
        button_frame = ctk.CTkFrame(anomaly_window)
        button_frame.pack(pady=10)

        ctk.CTkButton(
            button_frame,
            text="Packet Size Distribution",
            command=lambda: self.plot_packet_size_distribution(large_packets)
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            button_frame,
            text="Protocol Usage",
            command=lambda: self.plot_protocol_usage(protocol_counts)
        ).pack(side="left", padx=10)

        if traffic_spike:
            ctk.CTkButton(
                button_frame,
                text="Traffic Spikes",
                command=lambda: self.plot_traffic_spikes()
            ).pack(side="left", padx=10)

    def plot_packet_size_distribution(self, large_packets):
        """Plot the distribution of packet sizes with anomalies highlighted."""
        packet_lengths = [packet["length"] for packet in self.captured_packets]

        plt.figure(figsize=(10, 6))
        plt.hist(packet_lengths, bins=20, color="skyblue", edgecolor="black", alpha=0.7, label="Packet Sizes")
        if large_packets:
            for packet in large_packets:
                plt.annotate(
                    f"{packet['length']} bytes",
                    (packet["length"], 1),
                    color="red",
                    fontsize=10,
                    rotation=45,
                )
        plt.axvline(sum(packet_lengths) / len(packet_lengths), color="red", linestyle="--", label="Average Size")
        plt.title("Packet Size Distribution")
        plt.xlabel("Packet Length (bytes)")
        plt.ylabel("Frequency")
        plt.legend()
        plt.show()

    def plot_protocol_usage(self, protocol_counts):
        """Plot the usage of protocols."""
        plt.figure(figsize=(10, 6))
        plt.bar(protocol_counts.keys(), protocol_counts.values(), color="orange", alpha=0.7)
        plt.title("Protocol Usage")
        plt.xlabel("Protocol")
        plt.ylabel("Count")
        plt.show()

    def plot_traffic_spikes(self):
        """Visualize traffic spikes (placeholder data)."""
        plt.figure(figsize=(10, 6))
        plt.plot([1, 2, 3], [0.5, 1.5, 2.5], marker="o", color="green", label="Traffic Spikes")  # Placeholder data
        plt.title("Traffic Spikes")
        plt.xlabel("Time")
        plt.ylabel("Throughput (bps)")
        plt.legend()
        plt.show()


    def generate_summary(self):
        """Generate a detailed summary of traffic analysis."""
        if not self.captured_packets:
            self.status_label.configure(text="No packets to summarize.")
            return

        # Count packets by protocol
        protocol_counts = Counter(packet["proto_name"] for packet in self.captured_packets if packet["proto_name"] != "N/A")
        most_common_protocol = protocol_counts.most_common(1)[0] if protocol_counts else ("None", 0)

        # Calculate average, max, and min packet sizes
        packet_sizes = [packet["length"] for packet in self.captured_packets]
        avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        max_packet_size = max(packet_sizes) if packet_sizes else 0
        min_packet_size = min(packet_sizes) if packet_sizes else 0

        # Detect large packets
        threshold = 1000  # Example threshold for large packets
        large_packets = [packet for packet in self.captured_packets if packet["length"] > threshold]

        # Calculate throughput (bps)
        elapsed_time = (datetime.datetime.now() - self.start_time).total_seconds()
        avg_throughput = (self.total_bytes * 8) / elapsed_time if elapsed_time > 0 else 0

        # Count unique protocols
        unique_protocols = len(protocol_counts)

        # Top 5 protocols
        top_protocols = protocol_counts.most_common(5)

        # Traffic direction (based on IPs)
        src_ips = Counter(packet["src_display"].split(" | ")[1] for packet in self.captured_packets if "|" in packet["src_display"])
        dst_ips = Counter(packet["dst_display"].split(" | ")[1] for packet in self.captured_packets if "|" in packet["dst_display"])
        incoming_traffic = sum(dst_ips.values())
        outgoing_traffic = sum(src_ips.values())

        # Risk-level statistics
        risk_levels = Counter(packet["risk_level"] for packet in self.captured_packets if "risk_level" in packet)
        risk_stats = (
            f"Low: {risk_levels.get('low', 0)}, Medium: {risk_levels.get('medium', 0)}, "
            f"High: {risk_levels.get('high', 0)}, Critical: {risk_levels.get('critical', 0)}"
        )

        # Unique connections (source-destination pairs)
        unique_connections = len(set((packet["src_display"], packet["dst_display"]) for packet in self.captured_packets))

        # Build the summary string
        summary = (
            f"Traffic Summary:\n"
            f"- Total Packets: {len(self.captured_packets)}\n"
            f"- Average Packet Size: {avg_packet_size:.2f} bytes\n"
            f"- Min Packet Size: {min_packet_size} bytes\n"
            f"- Max Packet Size: {max_packet_size} bytes\n"
            f"- Throughput: {avg_throughput:.2f} bps\n"
            f"- Risk Levels: {risk_stats}\n"
            f"- Large Packets (> {threshold} bytes): {len(large_packets)} detected\n"
            f"- Unique Protocols: {unique_protocols}\n"
            f"- Top Protocols: {', '.join([f'{proto} ({count})' for proto, count in top_protocols])}\n"
            f"- Incoming Traffic: {incoming_traffic} packets\n"
            f"- Outgoing Traffic: {outgoing_traffic} packets\n"
            f"- Unique Connections: {unique_connections}\n"
        )

        # Show in a pop-up window
        summary_window = ctk.CTkToplevel(self.frame)
        summary_window.title("Traffic Summary")
        summary_window.geometry("500x400")

        ctk.CTkLabel(summary_window, text="Traffic Analysis Summary", font=("Arial", 16, "bold")).pack(pady=10)
        summary_text = ctk.CTkTextbox(summary_window, wrap="word")
        summary_text.pack(fill="both", expand=True, padx=10, pady=10)
        summary_text.insert("1.0", summary)
        summary_text.configure(state="disabled")

    def setup_ui(self):
        """Set up the UI for this sniffing session."""
        # Define Treeview style for dark mode
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background="#2b2b2b",
            foreground="white",
            fieldbackground="#2b2b2b",
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", "#3a3a3a")])

        style.configure(
            "Treeview.Heading",
            background="#2b2b2b",  # Dark background matching the theme
            foreground="#ffffff",  # White text
            font=("Arial", 12, "normal"),  # Softer font style
            borderwidth=0,  # No sharp edges
            relief="flat",  # Flat appearance
            padding=6,  # Add padding for a rounded feel
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#1f6aa5")],  # Match button hover color
            relief=[("active", "flat")],  # Keep it flat on hover
        )

        # Top Frame for Controls
        top_frame = ctk.CTkFrame(self.frame)
        top_frame.pack(fill="x", pady=10, padx=10)

        # Add Dark Mode Toggle Button
        self.dark_mode_var = ctk.BooleanVar(value=True)  # Default to dark mode
        ctk.CTkCheckBox(
            top_frame,
            text="Dark Mode",
            variable=self.dark_mode_var,
            command=self.toggle_theme,
        ).pack(side="right", padx=5)


        def get_available_interfaces():
            """Fetch Scapy-compatible network interfaces with IP addresses for display."""
            try:
                interfaces = get_if_list()
                readable_interfaces = {}

                for iface in interfaces:
                    try:
                        ip_address = get_if_addr(iface)
                        if ip_address and ip_address != "0.0.0.0":
                            # Store mapping of IP to interface
                            readable_interfaces[ip_address] = iface
                    except Exception:
                        pass

                return readable_interfaces if readable_interfaces else {"No Valid IP Addresses Found": None}

            except Exception as e:
                print(f"Error fetching interfaces: {e}")
                return {"No Interfaces Found": None}
                # Interface Selection (Dropdown + Manual Entry)
        ctk.CTkLabel(top_frame, text="Interface IP:").pack(side="left", padx=5)

        # Dropdown for detected IPs
        self.interface_mapping = get_available_interfaces()
        interface_list = list(self.interface_mapping.keys())  # Show only IPs in the dropdown

        self.interface_var = ctk.StringVar(value="Select or Type IP")
        self.interface_dropdown = ctk.CTkComboBox(
            top_frame,
            variable=self.interface_var,
            values=interface_list,
            state="readonly"
        )
        self.interface_dropdown.pack(side="left", padx=5)

        # Manual IP entry for flexibility
        self.manual_interface_var = ctk.StringVar()
        self.manual_interface_entry = ctk.CTkEntry(
            top_frame,
            textvariable=self.manual_interface_var,
            placeholder_text="Or type IP manually"
        )
        self.manual_interface_entry.pack(side="left", padx=5)

        self.max_bandwidth_var = ctk.StringVar(value="1000000")  # Default to 1 Mbps
      

        # Packet count
        ctk.CTkLabel(top_frame, text="Packet Count:").pack(side="left", padx=5)
        self.packet_count_var = ctk.StringVar(value="10")
        ctk.CTkEntry(top_frame, textvariable=self.packet_count_var).pack(side="left", padx=5)

        # Promiscuous Mode
        self.promiscuous_mode_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(top_frame, text="Promiscuous Mode", variable=self.promiscuous_mode_var).pack(side="left", padx=5)

        # Buttons for Control
        ctk.CTkButton(top_frame, text="Start Capture", command=self.start_capture).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Stop Capture", command=self.stop_capture).pack(side="left", padx=5)
        # ctk.CTkButton(
        #     top_frame,
        #     text="Geo-Location Map",
        #     command=self.geo_locate_ips
        # ).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Load PCAP", command=self.load_pcap_file).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Save Packets", command=self.save_packets).pack(side="left", padx=5)
        # Filters Section
        filter_frame = ctk.CTkFrame(self.frame)
        filter_frame.pack(fill="x", pady=10, padx=10)

        dark_frame = ctk.CTkFrame(self.frame)
        dark_frame.pack(fill="x",  pady=10, padx=10)

        ctk.CTkButton(dark_frame, text="Reset Filters", command=self.reset_filters).pack(side="left", padx=5)

        # Source IP
        ctk.CTkLabel(filter_frame, text="Source IP:").grid(row=0, column=0, padx=5, pady=5)
        self.src_ip_var = ctk.StringVar()
        ctk.CTkComboBox(filter_frame, variable=self.src_ip_var, values=["192.168.1.1", "127.0.0.1", ""]).grid(row=0, column=1, padx=5, pady=5)

        # Destination IP
        ctk.CTkLabel(filter_frame, text="Destination IP:").grid(row=0, column=2, padx=5, pady=5)
        self.dst_ip_var = ctk.StringVar()
        ctk.CTkComboBox(filter_frame, variable=self.dst_ip_var, values=["8.8.8.8", "10.0.0.1", ""]).grid(row=0, column=3, padx=5, pady=5)

        # Source Port
        ctk.CTkLabel(filter_frame, text="Source Port:").grid(row=1, column=0, padx=5, pady=5)
        self.src_port_var = ctk.StringVar()
        ctk.CTkComboBox(filter_frame, variable=self.src_port_var, values=["80", "443", "22", "53", ""]).grid(row=1, column=1, padx=5, pady=5)

        # Destination Port
        ctk.CTkLabel(filter_frame, text="Destination Port:").grid(row=1, column=2, padx=5, pady=5)
        self.dst_port_var = ctk.StringVar()
        ctk.CTkComboBox(filter_frame, variable=self.dst_port_var, values=["80", "443", "22", "53", ""]).grid(row=1, column=3, padx=5, pady=5)

        # Protocol
        ctk.CTkLabel(filter_frame, text="Protocol:").grid(row=2, column=0, padx=5, pady=5)
        self.protocol_var = ctk.StringVar()
        ctk.CTkComboBox(filter_frame, variable=self.protocol_var, values=["TCP", "UDP", "ICMP", ""]).grid(row=2, column=1, padx=5, pady=5)

        # Custom Filter
        ctk.CTkLabel(filter_frame, text="Custom Filter:").grid(row=2, column=2, padx=5, pady=5)
        self.custom_filter_var = ctk.StringVar()
        ctk.CTkEntry(filter_frame, textvariable=self.custom_filter_var).grid(row=2, column=3, padx=5, pady=5)

        # Scrollable Packet Table
        table_frame = ctk.CTkFrame(self.frame)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

                # Treeview for Packet Display
        self.packet_table = ttk.Treeview(
            table_frame,
            columns=("Time", "Source", "Destination", "Protocol", "Length"),
            show="headings",
            height=20,
        )

        # Enable column resizing
        for col in self.packet_table["columns"]:
            self.packet_table.column(col, anchor="center", stretch=True, width=150)

        # Define column headers
        self.packet_table.heading("Time", text="Time")
        self.packet_table.heading("Source", text="Source")
        self.packet_table.heading("Destination", text="Destination")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.heading("Length", text="Length")

        # Set column widths
        self.packet_table.column("Time", anchor="center", width=150)
        self.packet_table.column("Source", anchor="center", width=200)
        self.packet_table.column("Destination", anchor="center", width=200)
        self.packet_table.column("Protocol", anchor="center", width=100)
        self.packet_table.column("Length", anchor="center", width=70)

        # Scrollbar for Treeview
        scrollbar = ctk.CTkScrollbar(table_frame, command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=scrollbar.set)

        self.packet_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind Double-Click Event for Packet Details
        self.packet_table.bind("<Double-1>", self.show_packet_details)


        # Bottom Stats and Status Labels
        self.stats_label = ctk.CTkLabel(self.frame, text="Stats: Total Packets: 0, Data Rate: 0 Bytes/sec")
        self.stats_label.pack(fill="x", padx=10, pady=5)

        self.status_label = ctk.CTkLabel(self.frame, text="Status: Ready")
        self.status_label.pack(fill="x", padx=10, pady=5)