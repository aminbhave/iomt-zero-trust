"""
Legacy IoMT Device Simulator.

Replays real-world ECG data from the MIT-BIH Arrhythmia Database (PhysioNet)
as cleartext HTTP POST requests, mimicking a medical heart monitor running
on a legacy OS (Windows XP/7) with no native encryption.

Usage:
    python -m simulator.legacy_device [--sidecar-url URL] [--rate PACKETS_PER_SEC]
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import requests
import wfdb

DATA_DIR = Path(__file__).resolve().parent / "ecg_data"
DEFAULT_RECORD = "100"  # MIT-BIH record 100
PHYSIONET_DB = "mitdb"
CHUNK_SIZE = 360  # one second of data at 360 Hz sampling rate


def download_ecg_data(record: str = DEFAULT_RECORD) -> Path:
    """Download a MIT-BIH record if not already cached locally."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    local_path = DATA_DIR / record

    if not local_path.with_suffix(".dat").exists():
        print(f"[LegacyDevice] Downloading MIT-BIH record {record} ...")
        wfdb.dl_database(PHYSIONET_DB, str(DATA_DIR), records=[record])
        print(f"[LegacyDevice] Download complete -> {DATA_DIR}")

    return local_path


def load_ecg_signal(record_path: Path) -> np.ndarray:
    """Load the first channel of a WFDB record as a 1-D numpy array."""
    record = wfdb.rdrecord(str(record_path))
    signal = record.p_signal[:, 0]  # first lead (MLII)
    return signal


def replay_ecg(
    sidecar_url: str,
    signal: np.ndarray,
    rate: float = 1.0,
    device_id: str = "ecg_monitor_001",
    tenant_id: str = "tenant_A",
    max_packets: int | None = None,
):
    """Stream ECG chunks as cleartext HTTP POSTs to the sidecar proxy.

    Parameters
    ----------
    sidecar_url : str
        The sidecar's ``/ingest`` endpoint.
    signal : np.ndarray
        Full ECG signal array.
    rate : float
        Packets per second (1.0 = real-time at 360 Hz per chunk).
    max_packets : int or None
        Stop after this many packets (None = stream entire signal).
    """
    total_chunks = len(signal) // CHUNK_SIZE
    if max_packets:
        total_chunks = min(total_chunks, max_packets)

    interval = 1.0 / rate
    sent = 0

    print(
        f"[LegacyDevice] Streaming {total_chunks} ECG packets "
        f"@ {rate} pkt/s to {sidecar_url}"
    )

    for i in range(total_chunks):
        chunk = signal[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]

        payload = {
            "device_id": device_id,
            "tenant_id": tenant_id,
            "timestamp": time.time(),
            "seq": i,
            "ecg_samples": chunk.tolist(),
        }

        try:
            resp = requests.post(
                sidecar_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            status = resp.status_code
        except requests.RequestException as exc:
            status = f"ERR: {exc}"

        sent += 1
        print(
            f"  [{sent}/{total_chunks}] seq={i}  "
            f"size={len(json.dumps(payload))} bytes  status={status}"
        )

        time.sleep(interval)

    print(f"[LegacyDevice] Done. Sent {sent} packets.")


def main():
    parser = argparse.ArgumentParser(description="Legacy IoMT ECG Simulator")
    parser.add_argument(
        "--sidecar-url",
        default="http://localhost:8000/ingest",
        help="Sidecar proxy ingest endpoint",
    )
    parser.add_argument(
        "--rate", type=float, default=1.0, help="Packets per second"
    )
    parser.add_argument(
        "--record", default=DEFAULT_RECORD, help="MIT-BIH record ID"
    )
    parser.add_argument(
        "--max-packets", type=int, default=None, help="Max packets to send"
    )
    parser.add_argument(
        "--device-id", default="ecg_monitor_001", help="Device identifier"
    )
    parser.add_argument(
        "--tenant-id", default="tenant_A", help="Tenant identifier"
    )
    args = parser.parse_args()

    record_path = download_ecg_data(args.record)
    signal = load_ecg_signal(record_path)
    print(f"[LegacyDevice] Loaded {len(signal)} samples from record {args.record}")

    replay_ecg(
        sidecar_url=args.sidecar_url,
        signal=signal,
        rate=args.rate,
        device_id=args.device_id,
        tenant_id=args.tenant_id,
        max_packets=args.max_packets,
    )


if __name__ == "__main__":
    main()
