
# 🛡️ NetShield – Suspicious Network Activity Detection System

## 📌 About the Project

NetShield is a Python-based network security project designed to
analyze network traffic and identify potentially suspicious
network activities.

The system analyzes packet information, tracks network flows,
and uses rule-based detection techniques to identify patterns
such as port scanning, traffic spikes, and repeated TCP SYN attempts.

The main objective is to develop a simple and understandable
Network Intrusion Detection System (NIDS).

---

## 🎯 Project Objectives

- Analyze network packets using Python.
- Extract source IP, destination IP, ports, protocol and packet size.
- Track network flows and source IP activity.
- Detect suspicious network behavior.
- Generate security alerts based on predefined rules.
- Build a dashboard to visualize network activity (planned).

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Scapy | Packet analysis and PCAP processing |
| FastAPI | Backend API (planned) |
| SQLite | Database (planned) |
| React | Frontend dashboard (planned) |
| Git & GitHub | Version control and collaboration |

---

## 📂 Project Structure

```text
NetShield/
│
├── backend/                  # Backend development
│
├── engine/
│   ├── packet_capture.py     # Reads and analyzes PCAP files
│   ├── flow_tracker.py       # Groups and tracks network flows
│   └── detection_engine.py   # Detects suspicious activity
│
├── datasets/
│   ├── generate_sample.py    # Generates synthetic packets
│   └── sample.pcap           # Generated sample dataset
│
├── tests/                    # Testing
│
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation
└── .gitignore                # Ignored files
```

---

## ⚙️ Features Implemented

### 1. Packet Analyzer

- Reads offline PCAP files using Scapy.
- Extracts source and destination IP addresses.
- Identifies TCP, UDP and ICMP protocols.
- Extracts source and destination ports.
- Extracts packet timestamps, sizes and TCP flags.

### 2. Custom Dataset Generation

- Generates synthetic network packets.
- Includes TCP, UDP and ICMP traffic.
- Simulates a TCP SYN port scanning pattern.
- Saves generated traffic as a PCAP file.

### 3. Flow Tracker

- Groups packets using a five-tuple:
  Source IP, Destination IP, Source Port,
  Destination Port and Protocol.
- Tracks packet count and total bytes.
- Records first-seen and last-seen timestamps.
- Maintains recent source IP activity.

### 4. Detection Engine

Currently implements three rule-based detections:

| Detection | Threshold | Severity |
|---|---|---|
| Possible Port Scan | 20 or more unique destination ports | High |
| Traffic Spike | 100 or more packets | Medium |
| Repeated SYN Attempts | 30 or more TCP SYN packets | High |

Note: These are initial demonstration thresholds.
They are not universal security standards.

---

## 💻 Installation and Setup

### Prerequisites

- Python 3.10 or above
- Git
- Visual Studio Code (recommended)

### Step 1: Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/NetShield.git
cd NetShield
```

### Step 2: Create a virtual environment

```bash
python -m venv venv
```

### Step 3: Activate the virtual environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### Step 4: Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ How to Run the Project

Run these commands from the main NetShield directory.

### Step 1: Generate sample network traffic

```bash
python datasets/generate_sample.py
```

### Step 2: Analyze packets

```bash
python engine/packet_capture.py datasets/sample.pcap
```

### Step 3: Track network flows

```bash
python engine/flow_tracker.py
```

### Step 4: Detect suspicious activity

```bash
python engine/detection_engine.py
```

The detection engine analyzes the generated dataset and
prints alerts for patterns that meet the configured thresholds.

---

## 📊 Current Development Status

- [x] Project structure created
- [x] Python virtual environment configured
- [x] Custom PCAP dataset generator
- [x] Packet analyzer
- [x] Flow tracker
- [x] Rule-based detection engine
- [ ] FastAPI backend integration
- [ ] SQLite database integration
- [ ] React dashboard
- [ ] Real-time alert updates
- [ ] Machine learning-based anomaly detection
- [ ] Testing with public network intrusion datasets

---

## 🚀 Future Enhancements

- Real-time network traffic monitoring.
- Interactive security dashboard.
- Live alert notifications.
- Machine learning-based anomaly detection.
- Integration with CIC-IDS2017 dataset.
- Alert history and reporting.
- Improved detection accuracy and evaluation.

---

## 👥 Team Collaboration

This project is developed collaboratively using GitHub.

Team members can contribute through branches and pull requests.

---

## ⚠️ Disclaimer

NetShield is an educational cybersecurity project.
It is intended for defensive network monitoring and
authorized testing only.

The current implementation uses synthetic packet data
and basic rule-based detection. Alerts indicate potentially
suspicious patterns and do not independently prove malicious activity.

---

## 📜 License

To be decided.
