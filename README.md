# ScapyAI

ScapyAI is a local-first network intelligence dashboard built with Python, FastAPI, and Scapy. Describe a packet analysis task in natural language, upload a PCAP, or run a controlled live capture. Results include protocol statistics, top talkers, packet evidence, and lightweight heuristic detections for high-volume sources and SYN-heavy traffic.

## Run locally

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` in a browser. Live capture may require administrator privileges and a capture driver on Windows. PCAP analysis works without elevated privileges.

## Safety model

- The API exposes named operations in `app/tools.py`; user input never becomes Python code.
- Natural-language commands select one of the reviewed tools: `capture_packets`, `analyze_pcap`, `filter_packets`, or `authorized_probe`.
- Uploads accept only `.pcap` and `.pcapng` files and are stored under `data/uploads` using the sanitized basename.
- Active testing is disabled unless the request includes `authorized: true`, and targets must be private or loopback IP addresses.
- The current active-test tool is a dry-run placeholder. Add any lab-specific packet generation only after an explicit authorization and review flow is in place.

## Project layout

```text
app/                 FastAPI routes, request models, and Scapy tools
static/              Dashboard HTML, CSS, and browser behavior
data/uploads/        Local PCAP workspace (ignored captures should be added to .gitignore)
requirements.txt     Runtime dependencies
```

The command router is deliberately deterministic in this starter implementation. A future AI planner can be inserted before it, provided the planner emits a validated tool name and arguments rather than executable code.
