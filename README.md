# Network Device Health Monitoring System

## Project Overview
A Python-based web application that monitors network device availability, connectivity, performance metrics, and faults through a centralized dashboard.

## Features
- Monitor router, switch, and server status.
- Check connectivity using ICMP ping and TCP port checks.
- Monitor CPU and memory usage where supported.
- Generate alerts for unreachable devices and threshold violations.
- Display performance charts and device health.
- Store monitoring history in SQLite.
- Export monitoring data as CSV.
- Simulate faults for testing alerts.

## Technologies Used
- Python
- Streamlit
- SQLite
- Pandas and NumPy
- Plotly
- psutil
- SNMP
- Scikit-learn for anomaly detection and forecasting

## Project Structure

```text
NetworkHealthMonitor/
├── app.py
├── snmpagent.py
├── snmplite.py
├── .gitignore
└── README.md
```

## Installation and Execution

### 1. Install dependencies

```bash
pip install streamlit pandas numpy plotly psutil scikit-learn
```

Install any additional dependencies required by the project.

### 2. Start the SNMP agent

```bash
python snmpagent.py
```

### 3. Start the dashboard

Open another terminal and run:

```bash
python -m streamlit run app.py
```

Open the local URL displayed in the terminal.

## Note
The project combines real connectivity checks and local computer monitoring with simulated device data. CPU and memory metrics are available only where supported.

## Expected Outcome
A dashboard displaying device status, performance metrics, connectivity, fault alerts, and monitoring history.
