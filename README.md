# Project: SentinelFlow – Real-Time Network Malware Detection System

## Overview
SentinelFlow is a real-time network security monitoring system designed to detect malicious network activity using machine learning and flow-based traffic analysis. The system captures live network packets, reconstructs bidirectional flows, extracts statistical traffic features, and applies trained machine learning models to classify traffic as benign or malicious.

The project demonstrates how modern cybersecurity tools combine network telemetry, feature engineering, and machine learning to identify attacks such as denial-of-service attempts, brute-force activity, and abnormal traffic patterns.

SentinelFlow operates in two modes:

1. **Live Monitoring Mode** – captures packets from a network interface in real time.
2. **Dataset Analysis Mode** – analyzes PCAP or CSV datasets to evaluate detection performance.

---

# Architecture

The system is organized into modular components that reflect the stages of a network detection pipeline.

```
Packet Capture
      │
      ▼
Flow Reconstruction
      │
      ▼
Feature Extraction
      │
      ▼
Traffic Filtering
      │
      ▼
ML Detection Engine
      │
      ▼
Attack Classification
      │
      ▼
Alert Logging + Explanations
```

Each stage is implemented in a dedicated module to maintain separation of concerns and improve maintainability.

---

# Core Components

## Packet Capture
Location:

```
src/capture/
```

The capture module uses **Scapy** to monitor network interfaces and stream packets into the system.

Capabilities:

- Enumerate available interfaces
- Automatically select the interface with the highest traffic
- Stream packets continuously
- Replay packets from PCAP datasets

Key files:

```
sniff.py
replay.py
probe_interfaces.py
```

---

# Flow Reconstruction
Location:

```
src/flows/
```

Network packets are aggregated into **bidirectional flows**, representing a full communication session between two endpoints.

A flow is uniquely identified by:

```
(src_ip, src_port, dst_ip, dst_port, protocol)
```

The flow system maintains an in-memory flow table and expires flows using two timers:

| Timer | Purpose |
|------|--------|
| Inactive Timeout | Flow ends after inactivity |
| Active Timeout | Flow forcibly closed after long duration |

Key files:

```
flow_key.py
flow_record.py
flow_table.py
```

---

# Feature Extraction
Location:

```
src/features/extractor.py
```

Each completed flow is converted into numerical features used by the ML models.

Examples of extracted features:

- Flow duration
- Forward / reverse packet counts
- Forward / reverse byte counts
- Packet rate
- Byte rate
- Packet size statistics
- Inter-arrival time statistics
- TCP flag counts

These features mirror those used in common network intrusion datasets such as CIC-IDS.

The extractor guarantees that live flows produce the same feature schema used during model training.

---

# Traffic Filtering
Location:

```
src/detection/filtering.py
```

Before sending traffic to the ML engine, the system performs lightweight filtering to eliminate irrelevant traffic and tag flows with contextual metadata.

Examples:

Hard skips:

- loopback traffic
- multicast traffic
- broadcast traffic
- extremely small flows

Context tags:

- DNS
- HTTP
- HTTPS
- ephemeral ports
- high packet rate
- short flows

Filtering reduces noise while preserving potentially malicious flows.

---

# Machine Learning Detection
Location:

```
src/detection/
```

The detection engine uses two models:

### Binary Model

Determines whether traffic is:

```
benign
malicious
```

### Multiclass Model

If traffic is suspicious, the second model predicts the **attack family**.

Possible classes include:

- DoS
- DDoS
- Port Scan
- Brute Force
- Bot activity
- Web attack
- Unknown suspicious

The system uses probability thresholds to determine when alerts should be raised.

---

# Attack Explanation Engine
Location:

```
src/detection/explainer.py
```

To improve interpretability, the system generates human-readable explanations for each alert.

Example reasoning:

```
- high packet rate
- one-way traffic pattern
- asymmetric traffic volume
- unusual destination port
```

This makes alerts understandable to analysts instead of presenting only a raw model score.

---

# Alert Logging
Location:

```
src/alerts/logger.py
```

Alerts and flow records are stored in structured logs.

Two log streams are generated:

```
logs/alerts.jsonl
logs/flows.jsonl
```

Each alert includes:

- timestamp
- source / destination
- attack family
- confidence
- severity
- explanation

These logs can later be ingested into SIEM systems or analytics pipelines.

---

# Runtime Monitoring

The system prints operational statistics every 30 seconds:

Example status output:

```
[STATUS] uptime=00:10:30
analyzed_packets=25000
skipped_flows=400
ml_analyzed_flows=3200
completed_flows=3500
alerts=12
active_flows=20
avg_cpu=12%
avg_memory=6%
```

This allows operators to verify system performance and traffic load.

---

# Dataset Analysis Mode

The system can also analyze datasets offline.

Supported formats:

```
.pcap
.pcapng
.csv
```

Commands:

```
python src/dataset_main.py dataset.pcap

python src/dataset_main.py dataset.csv
```

CSV datasets must contain the same feature columns used during training.

---

# Machine Learning Training Pipeline

Location:

```
src/training/
```

The training pipeline prepares multiple datasets under a unified schema.

Steps:

1. Dataset discovery
2. Feature alignment
3. Label mapping
4. Dataset merging
5. Model training
6. Model evaluation

Two models are produced:

```
binary detector
multiclass attack classifier
```

The models are stored as joblib artifacts:

```
data/models/
```

Each artifact contains:

```
model
feature_columns
metadata
```

---

# Project Structure

```
src/

alerts/        alert logging
capture/       packet capture
common/        configuration and runtime utilities
datasets/      dataset preparation scripts
detection/     ML detection engine
features/      feature extraction
flows/         network flow tracking
training/      model training pipeline

main.py        live network monitoring
replay_main.py dataset replay
dataset_main.py dataset analyzer
```

---

# Example Usage

Live monitoring:

```
python src/main.py
```

Analyze PCAP:

```
python src/dataset_main.py traffic.pcap
```

Analyze CSV dataset:

```
python src/dataset_main.py dataset.csv
```

---

# Key Technical Concepts Demonstrated

This project demonstrates several important cybersecurity engineering concepts:

- Real-time packet capture
- Flow-based network analysis
- Feature engineering for network traffic
- Machine learning inference pipelines
- Streaming processing systems
- Runtime monitoring and telemetry

---

# Future Improvements

Potential extensions include:

- model retraining with additional datasets
- integration with SIEM platforms
- real-time dashboards
- distributed capture agents
- deep packet inspection features

---

# Conclusion

This project provides a modular and extensible foundation for building machine-learning-based network intrusion detection systems.

The project demonstrates how modern security tools can combine traffic telemetry, statistical analysis, and machine learning to identify malicious behavior in real time.

