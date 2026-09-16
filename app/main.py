from __future__ import annotations

import re
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .models import CommandRequest, CommandResponse
from .tools import analyze_pcap, authorized_probe, capture_packets, filter_packets

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="ScapyAI", version="0.1.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ScapyAI"}


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)) -> dict:
    started = perf_counter()
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng file.")
    safe_name = Path(file.filename).name
    destination = UPLOAD_DIR / safe_name
    destination.write_bytes(await file.read())
    try:
        result = analyze_pcap(destination)
        result["latency_ms"] = round((perf_counter() - started) * 1000, 1)
        return result
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse capture: {exc}") from exc


@app.post("/api/command", response_model=CommandResponse)
def command(request: CommandRequest) -> CommandResponse:
    started = perf_counter()
    text = request.command.lower().strip()
    try:
        if any(word in text for word in ("capture", "sniff", "listen")):
            data = capture_packets()
            data["latency_ms"] = round((perf_counter() - started) * 1000, 1)
            return CommandResponse(intent="capture", tool="capture_packets", summary=f"Captured {data['packet_count']} packets and grouped them by protocol.", data=data)
        if "filter" in text and any(name in text for name in ("tcp", "udp", "icmp", "arp", "dns", "ip")):
            protocol = next(name for name in ("tcp", "udp", "icmp", "arp", "dns", "ip") if name in text)
            latest = max(UPLOAD_DIR.glob("*.pcap*"), key=lambda path: path.stat().st_mtime, default=None)
            if latest is None:
                raise ValueError("Upload a PCAP before filtering it.")
            data = filter_packets(latest, protocol)
            data["latency_ms"] = round((perf_counter() - started) * 1000, 1)
            return CommandResponse(intent="filter", tool="filter_packets", summary=f"Found {data['packet_count']} {protocol.upper()} packets in {latest.name}.", data=data)
        if any(word in text for word in ("test", "probe", "scan")):
            match = re.search(r"(?:test|probe|scan)\s+(?:host\s+)?([0-9.]+)", text)
            if not match:
                raise ValueError("Name a private or loopback target, for example: probe 127.0.0.1")
            data = authorized_probe(match.group(1), request.authorized)
            data["latency_ms"] = round((perf_counter() - started) * 1000, 1)
            return CommandResponse(intent="authorized_test", tool="authorized_probe", summary="The lab action was accepted but no packet was sent.", data=data, safety_note="Active actions are restricted to explicitly authorized private or loopback targets.")
        latest = max(UPLOAD_DIR.glob("*.pcap*"), key=lambda path: path.stat().st_mtime, default=None)
        if latest is None:
            raise ValueError("Upload a PCAP or ask for a live capture to begin analysis.")
        data = analyze_pcap(latest)
        data["latency_ms"] = round((perf_counter() - started) * 1000, 1)
        return CommandResponse(intent="analysis", tool="analyze_pcap", summary=f"Analyzed {data['packet_count']} packets from {latest.name}.", data=data)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
