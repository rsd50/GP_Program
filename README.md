Multi-Session Packet Sniffer

📌 Project Overview

Multi-Session Packet Sniffer is a network traffic analysis tool that allows users to efficiently capture, filter, and analyze network packets. It provides an intuitive and user-friendly interface that balances simplicity for casual users and advanced features for expert users. The tool supports multi-session packet sniffing, real-time traffic visualization, protocol distribution analysis, and anomaly detection.

🎯 Key Features

Multi-Session Support – Run multiple packet sniffing sessions simultaneously.

Real-time Packet Capture – Capture live network traffic with filtering options.

Traffic Monitoring & Visualization – Monitor packet flow, network utilization, and protocol distribution.

Anomaly Detection – Identify large packets, uncommon protocols, and traffic spikes.

PCAP File Support – Load and save network captures in .pcap format.

Risk-Based Packet Filtering – Categorize packets by risk levels (Low, Medium, High, Critical).

Session Comparison – Compare multiple session traffic to detect patterns and anomalies.

User-Friendly UI – Simplified and intuitive design for both casual and expert users.

🛠️ Technologies Used

Programming Language: Python

Libraries & Tools:

Scapy – Packet sniffing and analysis

CustomTkinter – Modern UI for Python applications

Matplotlib – Data visualization and graph plotting

NetworkX – Network flow visualization

Cryptography – Secure encryption for packet storage

🚀 Installation & Setup

1️⃣ Prerequisites

Ensure you have Python 3.8+ installed on your system. You can download it from:
Python Official Website

2️⃣ Install Required Dependencies

Run the following command to install the required libraries:

pip install -r requirements.txt

3️⃣ Running the Application

Execute the following command to start the packet sniffer:

python main.py

🎛️ How to Use

Launch the Application – Run main.py to start the GUI.

Start a Session – Click "New Session" to begin sniffing packets.

Apply Filters – Use filters to capture specific packets based on IP, port, or protocol.

Monitor Traffic – View real-time network statistics.

Detect Anomalies – Identify high-risk packets and suspicious activities.

Save & Load Captures – Export captured packets as .pcap or encrypted files.

Compare Sessions – Analyze packet distributions across different sessions.

📊 Session Comparison & Risk Analysis

Users can compare multiple packet capture sessions using the built-in comparison window.

The application classifies packets into different risk levels and provides insights on potential security threats.

📝 Future Improvements

Implement Geo-location Mapping for IP address tracking.

Add AI-based anomaly detection for deeper security insights.

Enhance UI with dark/light mode toggle.

🤝 Contributors

Saleh alsaleh – Lead Developer

Abdullah alsalamah – UI/UX Designer

Rawaf aldowsary – Network Security Specialist

Osama alqefary - Backend Devolper
