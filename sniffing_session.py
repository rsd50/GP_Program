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
from live_traffic import start_live_traffic

class SniffingSession:
    def __init__(self, frame):
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

    def start_capture(self):
        """Start packet capturing."""
        selected_ip = self.interface_var.get()
        manual_ip = self.manual_interface_var.get().strip()

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
        """Update live statistics."""
        while self.is_running:
            elapsed_time = (datetime.datetime.now() - self.start_time).total_seconds()
            data_rate = self.total_bytes / elapsed_time if elapsed_time > 0 else 0
            self.stats_label.configure(text=f"Total Packets: {len(self.captured_packets)}\nData Rate: {data_rate:.2f} Bytes/sec")
            time.sleep(1)

    def stop_capture(self):
        """Stop packet capturing."""
        self.is_running = False
        self.status_label.configure(text="Status: Capture Stopped")

    def process_packet(self, packet):
        """Process and display a captured packet."""
        try:
            # Extract timestamp
            packet_time = float(packet.time) if isinstance(packet.time, Decimal) else packet.time
            timestamp = datetime.datetime.fromtimestamp(packet_time).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            timestamp = "N/A"

        # Extract MAC and IP addresses
        src_mac = packet.src if hasattr(packet, 'src') else "N/A"
        dst_mac = packet.dst if hasattr(packet, 'dst') else "N/A"
        src_ip, dst_ip, proto_name = "N/A", "N/A", "N/A"

        if packet.haslayer("IP"):
            src_ip, dst_ip = packet["IP"].src, packet["IP"].dst
            proto_name = get_protocol_name(packet["IP"].proto)  # Get protocol name

        src_display = f"{src_mac} | {src_ip}"
        dst_display = f"{dst_mac} | {dst_ip}"
        length = len(packet)

        # Update statistics
        self.captured_packets.append(packet)
        self.packet_counts[proto_name] += 1
        self.total_bytes += length

        # Insert packet data into the Treeview
        self.packet_table.insert("", "end", values=(timestamp, src_display, dst_display, proto_name, length))

    def show_packet_details(self, event):
        """Display detailed packet information using Scapy's packet.show() method."""
        selected_item = self.packet_table.selection()
        if not selected_item:
            return

        packet_index = self.packet_table.index(selected_item)  # Get index of selected packet

        if packet_index >= len(self.captured_packets):
            return  # Avoid out-of-range error

        packet = self.captured_packets[packet_index]

        # Create a new window for packet details
        details_window = ctk.CTkToplevel(self.frame)
        details_window.title("Packet Details")
        details_window.geometry("800x600")

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
            details_text.insert("1.0", packet_details)
            details_text.configure(state="disabled")  # Make it read-only

        except Exception as e:
            details_text.insert("1.0", f"❗ Error displaying packet details: {e}")
            details_text.configure(state="disabled")

        ctk.CTkButton(details_window, text="Close", command=details_window.destroy).pack(pady=10)


        
        
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






    def show_protocol_statistics(self):
        """Show a bar chart of protocol distribution."""
        protocols = [pkt["IP"].proto for pkt in self.captured_packets if pkt.haslayer("IP")]
        protocol_counts = Counter(protocols)
        plt.figure(figsize=(6, 4))
        plt.bar(protocol_counts.keys(), protocol_counts.values())
        plt.xlabel("Protocol")
        plt.ylabel("Count")
        plt.title("Protocol Distribution")
        
    def reset_filters(self):
        """Reset all filter fields to their default values."""
        self.src_ip_var.set("")
        self.dst_ip_var.set("")
        self.src_port_var.set("")
        self.dst_port_var.set("")
        self.protocol_var.set("")
        self.custom_filter_var.set("")

    

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
        ctk.CTkButton(top_frame, text="Show Stats", command=self.show_protocol_statistics).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Reset Filters", command=self.reset_filters).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Load PCAP", command=self.load_pcap_file).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Save Packets", command=self.save_packets).pack(side="left", padx=5)
        # Filters Section
        filter_frame = ctk.CTkFrame(self.frame)
        filter_frame.pack(fill="x", pady=10, padx=10)

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