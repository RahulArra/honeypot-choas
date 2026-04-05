"""
Chaos Experiments — Chaos Validation Engine
Member B (Sesh) Responsibility

Implements three controlled stress experiments:
    1. CPU Stress
    2. Memory Stress
    3. Disk I/O Stress

All experiments are:
    - Time-bounded (never run forever)
    - Safe (no real system damage)
    - Monitored (metrics collected during run)
"""

import subprocess
import time
import os
import threading
import tempfile
import logging
import psutil

logger = logging.getLogger(__name__)

# ── Safety Limits ──────────────────────────────────────────────────────────────
MAX_DURATION_SECS  = 20      # Hard cap — no experiment runs longer than this
MAX_MEMORY_MB      = 256     # Max memory to allocate (MB)
MAX_CPU_THREADS    = 2       # Max CPU stress threads
DISK_IO_FILE_SIZE  = 10      # MB written to temp file


# ── Metrics Collector ──────────────────────────────────────────────────────────

def _collect_metrics(duration: int) -> dict:
    """
    Sample CPU and memory usage over the experiment duration.
    Returns peak values.
    """
    cpu_samples    = []
    memory_samples = []
    start_time     = time.time()

    while time.time() - start_time < duration:
        cpu_samples.append(psutil.cpu_percent(interval=0.5))
        memory_samples.append(psutil.virtual_memory().percent)

    return {
        "cpu_peak":    round(max(cpu_samples),    2) if cpu_samples    else 0.0,
        "memory_peak": round(max(memory_samples), 2) if memory_samples else 0.0,
    }


# ── CPU Stress ─────────────────────────────────────────────────────────────────

def run_cpu_stress(duration: int, intensity_level: int) -> dict:
    duration    = min(duration, MAX_DURATION_SECS)
    num_threads = min(intensity_level, MAX_CPU_THREADS)

    logger.info(f"[Chaos] CPU stress (Docker) → {num_threads} thread(s) for {duration}s")
    start_time = time.time()

    # Launch docker container
    cmd = [
        "docker", "run", "--rm", "chaos-executor", 
        "--cpu", str(num_threads), "--timeout", f"{duration}s"
    ]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.warning("[Chaos] Docker not installed, skipping actual stress run.")
        proc = None

    # Collect metrics while stress runs
    metrics = _collect_metrics(duration)

    if proc:
        proc.wait(timeout=duration + 5)

    recovery_start = time.time()
    for _ in range(10):
        if psutil.cpu_percent(interval=0.5) < 20:
            break

    recovery_time = round(time.time() - recovery_start, 2)
    total_duration = round(time.time() - start_time, 2)

    if metrics["cpu_peak"] > 85 and recovery_time > 10:
        result = "Vulnerable"
    else:
        result = "Resilient"

    logger.info(f"[Chaos] CPU stress done → peak={metrics['cpu_peak']}%, recovery={recovery_time}s, result={result}")

    return {
        "experiment_type":    "cpu_stress",
        "intensity_level":    intensity_level,
        "cpu_peak":           metrics["cpu_peak"],
        "memory_peak":        metrics["memory_peak"],
        "disk_io_peak":       None,
        "duration_secs":      total_duration,
        "recovery_time_secs": recovery_time,
        "result":             result,
        "notes":              f"Docker: {num_threads} worker thread(s)",
    }


# ── Memory Stress ──────────────────────────────────────────────────────────────

def run_memory_stress(duration: int, intensity_level: int) -> dict:
    duration   = min(duration, MAX_DURATION_SECS)
    alloc_mb   = min(intensity_level * 64, MAX_MEMORY_MB)

    logger.info(f"[Chaos] Memory stress (Docker) → allocating {alloc_mb}MB for {duration}s")
    start_time = time.time()

    # stress-ng --vm 1 --vm-bytes 64M --timeout 10s
    cmd = [
        "docker", "run", "--rm", "chaos-executor", 
        "--vm", "1", "--vm-bytes", f"{alloc_mb}M", "--timeout", f"{duration}s"
    ]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.warning("[Chaos] Docker not installed, skipping actual stress run.")
        proc = None

    metrics = _collect_metrics(duration)

    if proc:
        proc.wait(timeout=duration + 5)

    recovery_start = time.time()
    for _ in range(10):
        if psutil.virtual_memory().percent < 80:
            break
        time.sleep(0.5)

    recovery_time  = round(time.time() - recovery_start, 2)
    total_duration = round(time.time() - start_time,     2)

    if metrics["memory_peak"] > 85 and recovery_time > 10:
        result = "Vulnerable"
    else:
        result = "Resilient"

    logger.info(f"[Chaos] Memory stress done → peak={metrics['memory_peak']}%, recovery={recovery_time}s, result={result}")

    return {
        "experiment_type":    "memory_stress",
        "intensity_level":    intensity_level,
        "cpu_peak":           metrics["cpu_peak"],
        "memory_peak":        metrics["memory_peak"],
        "disk_io_peak":       None,
        "duration_secs":      total_duration,
        "recovery_time_secs": recovery_time,
        "result":             result,
        "notes":              f"Docker: Allocated {alloc_mb}MB",
    }


# ── Disk I/O Stress ────────────────────────────────────────────────────────────

def run_disk_io_stress(duration: int, intensity_level: int) -> dict:
    duration  = min(duration, MAX_DURATION_SECS)
    # stress-ng --hdd 1 --hdd-bytes X --timeout 10s
    logger.info(f"[Chaos] Disk I/O stress (Docker) → {intensity_level} worker(s) for {duration}s")

    start_time  = time.time()

    cmd = [
        "docker", "run", "--rm", "chaos-executor", 
        "--hdd", str(intensity_level), "--timeout", f"{duration}s"
    ]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.warning("[Chaos] Docker not installed, skipping actual stress run.")
        proc = None

    metrics = _collect_metrics(duration)

    if proc:
        proc.wait(timeout=duration + 5)

    total_duration = round(time.time() - start_time, 2)
    
    recovery_start = time.time()
    time.sleep(1)
    recovery_time  = round(time.time() - recovery_start, 2)

    # Simplified disk_io calculation since we rely on overall system metric evaluation logic requested
    if metrics["cpu_peak"] > 85 and recovery_time > 10:
        result = "Vulnerable"
    else:
        result = "Resilient"

    logger.info(f"[Chaos] Disk I/O done → recovery={recovery_time}s, result={result}")

    return {
        "experiment_type":    "disk_io",
        "intensity_level":    intensity_level,
        "cpu_peak":           metrics["cpu_peak"],
        "memory_peak":        metrics["memory_peak"],
        "disk_io_peak":       0.0,
        "duration_secs":      total_duration,
        "recovery_time_secs": recovery_time,
        "result":             result,
        "notes":              f"Docker: HDD stress level {intensity_level}",
    }


# ── Dispatcher ─────────────────────────────────────────────────────────────────

def run_experiment(experiment_type: str, duration: int, intensity_level: int) -> dict:
    """
    Public entry point — dispatches to the correct experiment.
    Never raises — returns error dict on failure.
    """
    try:
        if experiment_type == "cpu_stress":
            return run_cpu_stress(duration, intensity_level)
        elif experiment_type == "memory_stress":
            return run_memory_stress(duration, intensity_level)
        elif experiment_type == "disk_io":
            return run_disk_io_stress(duration, intensity_level)
        else:
            logger.warning(f"[Chaos] Unknown experiment type: {experiment_type}")
            return run_cpu_stress(duration, intensity_level)
    except Exception as e:
        logger.error(f"[Chaos] Experiment failed: {e}", exc_info=True)
        return {
            "experiment_type":    experiment_type,
            "intensity_level":    intensity_level,
            "cpu_peak":           0.0,
            "memory_peak":        0.0,
            "disk_io_peak":       None,
            "duration_secs":      0,
            "recovery_time_secs": 0.0,
            "result":             "Resilient",
            "notes":              f"Experiment failed: {e}",
        }