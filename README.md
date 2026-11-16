# NetShield – Suspicious Network Activity Detection System

NetShield is a Python-based network security project designed to identify suspicious network activities by analyzing network packet data.

It detects potential threats such as port scanning, repeated TCP SYN attempts, and unusual traffic spikes. Detected alerts are stored in an SQLite database and displayed through a web-based dashboard.

## Features

- **Port Scan Detection:** Identifies devices accessing multiple destination ports.
- **Repeated SYN Detection:** Detects repeated TCP SYN connection attempts.
- **Traffic Spike Detection:** Identifies unusually high packet activity.
- **Alert Management:** Stores detected alerts in an SQLite database.
- **Duplicate Alert Prevention:** Prevents repeated alerts of the same type from the same IP within a 5-minute window.
- **Web Dashboard:** Displays alerts, severity statistics, charts, and filtering options.
- **REST API:** Uses FastAPI to manage and retrieve security alerts.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Detection engine |
| FastAPI | Backend API |
| SQLite | Database |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Dashboard functionality |
| Chart.js | Data visualization |
| Wireshark / PCAP | Network packet data format and analysis context |

## Project Structure

```text
Netshield/
│
├── backend/
│   ├── main.py
│   ├── database.py
│   └── netshield.db
│
├── engine/
│   ├── detection_engine.py
│   └── packet_capture.py
│
├── datasets/
│   └── sample.pcap
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── .gitignore
└── README.md
```

## How It Works

1. The system reads network packet data from a PCAP file.
2. The Python detection engine analyzes the packets.
3. It identifies suspicious activities using predefined detection rules.
4. Detected alerts are sent to the FastAPI backend.
5. The backend checks for duplicate alerts and stores new alerts in SQLite.
6. The frontend dashboard retrieves and displays the alerts.

## Detected Threats

| Threat | Description | Severity |
|---|---|---|
| Possible Port Scan | Accessing multiple destination ports | High |
| Repeated SYN Attempts | Repeated TCP SYN packets | High |
| Traffic Spike | Unusually high packet activity | Medium |

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Netshield
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install fastapi uvicorn requests scapy
```

### 5. Start the backend server

From the project root:

```bash
uvicorn backend.main:app --reload
```

Backend API:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### 6. Run the detection engine

Open another terminal, activate the virtual environment, and execute:

```bash
python engine/detection_engine.py
```

### 7. Open the frontend

Open `frontend/index.html` using the VS Code Live Server extension.

## Future Enhancements

- Real-time network packet monitoring.
- Email notifications for critical alerts.
- More advanced threat detection rules.
- IP-based threat intelligence integration.

## Project Objective

The main objective of NetShield is to provide a simple network monitoring and suspicious activity detection system that helps identify potentially harmful network behavior through packet analysis and a centralized dashboard.

---

**NetShield – Making Network Monitoring Simpler and Smarter