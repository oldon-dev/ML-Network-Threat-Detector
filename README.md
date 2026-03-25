# ML Network Analyzer

ML Network Analyzer is a Windows desktop application for real-time network monitoring and offline traffic analysis. It captures packets, reconstructs bidirectional flows, extracts traffic features, filters low-value traffic, applies machine learning models, and logs malicious detections with human-readable reasons.

The current desktop UI is a native `PySide6` application. It provides:

- live monitoring control
- dashboard metrics and threat views
- packet telemetry
- recent threat traffic
- flows sent to the ML engine with routing reasons
- dataset analysis jobs
- session history

## Main Features

- Live packet capture from a network interface
- Automatic interface selection when no interface is chosen
- Bidirectional flow reconstruction
- Lightweight flow filtering before ML scoring
- Binary malicious / benign classification
- Multiclass attack family prediction
- Human-readable detection reasons
- Structured JSONL logging for packets, flows, and alerts
- Native Windows desktop UI for monitoring and review
- Offline analysis of `.pcap`, `.pcapng`, and `.csv` datasets

## Desktop App

Main entry point:

```powershell
py src/app.py
```

The desktop application title is:

```text
ML Network Analyzer
```

Main tabs:

- Monitoring
- Dashboard
- Threats
- Sessions
- Packet Log
- Analysis

### Monitoring Tab

The Monitoring tab lets you:

- choose a capture interface
- start live monitoring
- stop live monitoring
- view live runtime status
- view monitoring worker console output

When monitoring is already active, the `Start Monitoring` button is disabled and `Stop Monitoring` is enabled.

### Dashboard Tab

The Dashboard shows:

- inline top metrics for alerts, packets, ML analyzed flows, active flows, and CPU
- a compact threat landscape
- recent threat traffic
- traffic sent to the ML engine and the routing reason

### Threats Tab

The Threats tab shows:

- recent alerts
- attack family
- severity
- score and confidence
- source and destination
- analyst reasons
- feature summary

### Sessions Tab

The Sessions tab shows archived monitoring sessions with:

- start and stop time
- uptime
- packet count
- threat count
- interface
- summary details

### Packet Log Tab

The Packet Log tab shows recent packet telemetry for the active session.

### Analysis Tab

The Analysis tab lets you launch offline analysis jobs against:

- `.pcap`
- `.pcapng`
- `.csv`

## Requirements

Python 3.11+ is recommended.

Install the base dependencies:

```powershell
pip install -r requirements.txt
```

Install the desktop UI dependency:

```powershell
pip install PySide6
```

Notes:

- `PySide6` is required for the current Windows desktop UI.
- Live capture relies on `scapy`.
- Packet capture may require elevated privileges depending on your adapter and Windows configuration.

## Running the Project

### 1. Launch the Desktop App

```powershell
py src/app.py
```

### 2. Run Live Monitoring Without the UI

```powershell
py src/main.py
```

### 3. Analyze a PCAP File

```powershell
py src/dataset_main.py path\to\traffic.pcap
```

### 4. Analyze a CSV Feature Dataset

```powershell
py src/dataset_main.py path\to\dataset.csv
```

## High-Level Pipeline

```text
Packet Capture
  -> Flow Reconstruction
  -> Feature Extraction
  -> Traffic Filtering
  -> ML Detection
  -> Attack Classification
  -> Alert Logging + Explanations
```

## Core Components

### Packet Capture

Location:

```text
src/capture/
```

Key files:

- `sniff.py`
- `replay.py`
- `probe_interfaces.py`

Responsibilities:

- enumerate interfaces
- auto-select the busiest interface
- capture live packets
- replay PCAP traffic

### Flow Reconstruction

Location:

```text
src/flows/
```

Key files:

- `flow_key.py`
- `flow_record.py`
- `flow_table.py`

Responsibilities:

- group packets into bidirectional flows
- track forward and reverse packet and byte counts
- expire inactive or long-running flows

### Feature Extraction

Location:

```text
src/features/extractor.py
```

Example features:

- flow duration
- forward and reverse packets
- forward and reverse bytes
- packets per second
- bytes per second
- packet size statistics
- inter-arrival statistics
- TCP flag counts

### Traffic Filtering

Location:

```text
src/detection/filtering.py
```

Filtering does two things:

1. skips obviously irrelevant traffic
2. tags flows with context before ML scoring

Examples of skip conditions:

- loopback traffic
- multicast traffic
- broadcast traffic
- too few packets
- too few bytes

Examples of tags:

- `dns`
- `http`
- `https`
- `short_flow`
- `high_packet_rate`
- `one_way`

### ML Detection

Location:

```text
src/detection/
```

The detection pipeline uses:

- one binary model for malicious / benign prediction
- one multiclass model for attack family prediction

### Explanations

Location:

```text
src/detection/explainer.py
```

Each alert can include reasons such as:

- high packet rate
- unusual destination port
- one-way traffic pattern
- suspicious communication pattern

### Logging

Location:

```text
src/alerts/logger.py
```

Main logs:

```text
logs/alerts.jsonl
logs/flows.jsonl
logs/packets.jsonl
logs/runtime_live.json
logs/session_history.json
```

What is logged:

- alerts with score, family, confidence, severity, and reasons
- flows with features, filter tags, and ML routing metadata
- packets for the active session
- runtime status snapshots
- completed monitoring session summaries

## Project Structure

```text
src/
  alerts/             alert, flow, and packet logging
  capture/            live and replay packet capture
  common/             config and runtime helpers
  dashboard_app/      payload building and runtime management
  datasets/           dataset preparation scripts
  detection/          filtering, classification, explanations
  features/           feature extraction
  flows/              flow tracking
  training/           model training and evaluation

  app.py              desktop app launcher
  qt_desktop_app.py   PySide6 desktop UI
  desktop_app.py      older Tk desktop UI
  main.py             live monitor worker
  dataset_main.py     offline dataset analysis
  replay_main.py      replay mode
```

## Training and Models

Training code is under:

```text
src/training/
```

Model artifacts are expected under:

```text
data/models/
```

The application expects model artifacts that include:

- the trained estimator
- the feature column list
- metadata used by the detector

## Operational Notes

- The dashboard refreshes frequently in the desktop UI.
- The monitoring worker writes runtime snapshots even though periodic heartbeat logs were removed from the console.
- Flows sent to the ML engine are logged with `sent_to_ml` and `decision_reason`.
- Existing logs from older runs may not contain the newer routing metadata fields.

## Known Constraints

- Real packet capture behavior depends on local adapter permissions and Windows packet capture support.
- The newer desktop UI requires `PySide6`.
- The older Tk UI file still exists in the repository, but `src/app.py` now launches the Qt desktop app.

## Suggested Next Improvements

- add packet and flow filtering controls in the UI
- add richer charting in the Qt dashboard
- add export for session summaries and alerts
- package the Qt desktop app into a Windows executable
- add model health and version panels
