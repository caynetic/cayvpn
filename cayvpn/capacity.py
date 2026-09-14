from __future__ import annotations

import os
import platform
import re
import shutil
from datetime import datetime, timezone
from dataclasses import asdict, dataclass
from pathlib import Path


BASELINE_CLIENTS = {
    (1, 1024): 5,
    (1, 2048): 15,
    (2, 4096): 35,
    (4, 8192): 75,
    (8, 16384): 150,
}

# Cloud providers advertise nominal RAM tiers, while Linux reports slightly
# less usable memory after firmware, kernel, and hypervisor reservations. A
# small tolerance keeps a marketed 2/4/8/16 GB VPS in its intended benchmark
# tier without promoting a materially smaller plan.
NOMINAL_MEMORY_FLOOR = 0.90

DRIVER_OVERHEAD = {
    "direct_ip": {"memory": 0, "clients": 1.0},
    "additional_ip": {"memory": 32, "clients": 1.0},
    "provider_tunnel": {"memory": 128, "clients": 0.85},
    "socks5": {"memory": 160, "clients": 0.70},
}


@dataclass(frozen=True)
class SystemResources:
    architecture: str
    vcpus: int
    memory_mb: int
    disk_free_mb: int
    interface_speed_mbps: int | None = None
    traffic_bytes: int = 0
    load_1m: float = 0.0
    active_clients: int = 0
    active_driver_processes: int = 0


@dataclass(frozen=True)
class CapacityEstimate:
    safe_active_clients: int
    max_stored_configs: int
    max_egress_profiles: int
    estimated_mbps: int
    limiting_factor: str
    confidence: str
    over_capacity: bool = False


def _memory_mb() -> int:
    try:
        text = Path("/proc/meminfo").read_text()
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB", text, re.MULTILINE)
        return int(match.group(1)) // 1024 if match else 0
    except OSError:
        return 0


def detect_resources(active_clients: int = 0, active_driver_processes: int = 0) -> SystemResources:
    usage = shutil.disk_usage(Path.cwd())
    interface = os.environ.get("CAYVPN_OUT_IFACE")
    if not interface:
        try:
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 1 and fields[1] == "00000000":
                    interface = fields[0]
                    break
        except OSError:
            interface = None
    speed = None
    traffic = 0
    load_1m = 0.0
    try:
        load_1m = float(Path("/proc/loadavg").read_text().split()[0])
    except (OSError, IndexError, ValueError):
        pass
    if interface and re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        try:
            value = int((Path("/sys/class/net") / interface / "speed").read_text().strip())
            speed = value if value > 0 else None
        except (OSError, ValueError):
            speed = None
        for direction in ("rx_bytes", "tx_bytes"):
            try:
                traffic += int((Path("/sys/class/net") / interface / "statistics" / direction).read_text().strip())
            except (OSError, ValueError):
                pass
    return SystemResources(
        architecture=platform.machine() or "unknown",
        vcpus=max(1, os.cpu_count() or 1),
        memory_mb=_memory_mb(),
        disk_free_mb=usage.free // (1024 * 1024),
        interface_speed_mbps=speed,
        traffic_bytes=traffic,
        load_1m=max(0.0, load_1m),
        active_clients=max(0, int(active_clients)),
        active_driver_processes=max(0, int(active_driver_processes)),
    )


def transfer_forecast(traffic_bytes: int, now: datetime | None = None) -> tuple[int, int]:
    """Return current-month usage and a simple month-end forecast in GB."""
    now = now or datetime.now(timezone.utc)
    used_gb = max(0, int(traffic_bytes)) // (1024**3)
    days_in_month = 31
    if now.month == 2:
        days_in_month = 29 if now.year % 4 == 0 and (now.year % 100 != 0 or now.year % 400 == 0) else 28
    elif now.month in {4, 6, 9, 11}:
        days_in_month = 30
    forecast = int(used_gb * days_in_month / max(1, now.day))
    return used_gb, forecast


def _baseline(vcpus: int, memory_mb: int) -> int:
    if memory_mb <= 0:
        return max(5, vcpus * 5)
    candidates = sorted(BASELINE_CLIENTS.items(), key=lambda item: item[0][0] * item[0][1])
    selected = candidates[0][1]
    for (cpu, memory), value in candidates:
        if vcpus >= cpu and memory_mb >= int(memory * NOMINAL_MEMORY_FLOOR):
            selected = value
    return selected


def calculate_capacity(
    resources: SystemResources,
    drivers: list[str] | None = None,
    transfer_allowance_gb: int | None = None,
    advertised_mbps: int | None = None,
) -> CapacityEstimate:
    drivers = drivers or ["direct_ip"]
    safe = _baseline(resources.vcpus, resources.memory_mb)
    memory_budget = max(0, resources.memory_mb - 512)
    overhead = 0
    factor = "cpu and memory"
    multiplier = 1.0
    for driver in drivers:
        profile = DRIVER_OVERHEAD.get(driver, DRIVER_OVERHEAD["provider_tunnel"])
        overhead += profile["memory"]
        multiplier *= profile["clients"]
    if memory_budget and overhead > memory_budget:
        safe = 1
        factor = "memory reserved for egress drivers"
    elif overhead:
        safe = max(1, int(safe * multiplier))
    if advertised_mbps:
        network_limit = max(1, int(advertised_mbps / 5))
        if network_limit < safe:
            safe = network_limit
            factor = "advertised network speed"
    if transfer_allowance_gb and transfer_allowance_gb < 100:
        safe = max(1, min(safe, transfer_allowance_gb // 10 or 1))
        factor = "monthly transfer allowance"
    if resources.load_1m > max(1.0, resources.vcpus * 1.5):
        safe = max(1, int(safe * 0.80))
        factor = "current system load"
    if resources.active_driver_processes > 0:
        safe = max(1, int(safe * max(0.50, 1.0 - min(0.40, resources.active_driver_processes * 0.03))))
        factor = "active egress and resolver processes"
    estimated = int((advertised_mbps or max(50, resources.vcpus * 100)) * (0.70 if overhead else 0.85))
    confidence = "high" if resources.memory_mb and resources.vcpus else "low"
    return CapacityEstimate(
        safe_active_clients=safe,
        max_stored_configs=max(4, safe * 4),
        max_egress_profiles=max(1, min(16, memory_budget // 256 if memory_budget else 1)),
        estimated_mbps=estimated,
        limiting_factor=factor,
        confidence=confidence,
        over_capacity=resources.active_clients > safe,
    )


def as_dict(resources: SystemResources, estimate: CapacityEstimate) -> dict:
    used_gb, forecast_gb = transfer_forecast(resources.traffic_bytes)
    return {"resources": asdict(resources), "estimate": asdict(estimate), "transfer": {"used_gb": used_gb, "forecast_gb": forecast_gb}}
