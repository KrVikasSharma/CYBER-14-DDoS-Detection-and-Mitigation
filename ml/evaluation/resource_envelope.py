import ctypes
import os
import platform
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from ml.evaluation.evidence import file_sha256, get_git_commit, utc_now


def _get_ram_info() -> dict[str, float | None]:
    """Retrieve actual physical system RAM using platform-specific APIs."""
    system = platform.system()
    if system == "Windows":
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                total_gb = round(stat.ullTotalPhys / (1024**3), 2)
                avail_gb = round(stat.ullAvailPhys / (1024**3), 2)
                return {
                    "total_ram_gb": total_gb,
                    "available_ram_gb": avail_gb,
                    "used_ram_gb": round(total_gb - avail_gb, 2),
                    "memory_load_percent": float(stat.dwMemoryLoad),
                }
        except Exception:
            pass
    elif system == "Linux":
        try:
            meminfo_path = Path("/proc/meminfo")
            if meminfo_path.exists():
                mem_data = {}
                for line in meminfo_path.read_text().splitlines():
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        mem_data[key] = int(val)
                total_kb = mem_data.get("MemTotal", 0)
                avail_kb = mem_data.get("MemAvailable", mem_data.get("MemFree", 0))
                total_gb = round(total_kb / (1024**2), 2)
                avail_gb = round(avail_kb / (1024**2), 2)
                return {
                    "total_ram_gb": total_gb,
                    "available_ram_gb": avail_gb,
                    "used_ram_gb": round(total_gb - avail_gb, 2),
                    "memory_load_percent": round(((total_gb - avail_gb) / total_gb) * 100, 1) if total_gb else None,
                }
        except Exception:
            pass

    return {
        "total_ram_gb": None,
        "available_ram_gb": None,
        "used_ram_gb": None,
        "memory_load_percent": None,
    }


def capture_environment_envelope() -> dict[str, Any]:
    """Capture full hardware and runtime environment envelope."""
    ram = _get_ram_info()
    return {
        "git_commit": get_git_commit(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "os_system": platform.system(),
        "os_release": platform.release(),
        "os_platform": platform.platform(),
        "cpu_processor": platform.processor(),
        "cpu_machine": platform.machine(),
        "cpu_logical_cores": os.cpu_count(),
        "active_threads": threading.active_count(),
        "total_ram_gb": ram["total_ram_gb"],
        "available_ram_gb": ram["available_ram_gb"],
        "used_ram_gb": ram["used_ram_gb"],
        "memory_load_percent": ram["memory_load_percent"],
        "recorded_at_utc": utc_now(),
    }


def capture_resource_envelope(
    operation: Callable[[], Any] | None = None,
    *,
    sample_count: int = 0,
) -> dict[str, Any]:
    """Measure resource and execution metrics during a defined operation."""
    env = capture_environment_envelope()
    if operation is None:
        return env

    start_time = time.perf_counter()
    result = operation()
    elapsed_sec = time.perf_counter() - start_time

    throughput = round(sample_count / elapsed_sec, 2) if (sample_count > 0 and elapsed_sec > 0) else None
    avg_latency_ms = round((elapsed_sec / sample_count) * 1000.0, 4) if (sample_count > 0 and elapsed_sec > 0) else None

    return {
        **env,
        "execution_metrics": {
            "elapsed_seconds": round(elapsed_sec, 4),
            "sample_count": sample_count,
            "throughput_flows_per_sec": throughput,
            "avg_latency_per_sample_ms": avg_latency_ms,
        },
        "operation_result": result if isinstance(result, (dict, list, int, float, str, bool)) else None,
    }
