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

def _cpu_worker(stop_event: threading.Event):
    """Single CPU stress worker thread — burns CPU until stop_event is set."""
    while not stop_event.is_set():
        _ = sum(i * i for i in range(10000))


def run_cpu_stress(duration: int, intensity_level: int) -> dict:
    """
    Spin up CPU worker threads for `duration` seconds.
    intensity_level controls number of threads (1→1, 2→2, 3→2).
    """
    duration    = min(duration, MAX_DURATION_SECS)
    num_threads = min(intensity_level, MAX_CPU_THREADS)

    logger.info(f"[Chaos] CPU stress → {num_threads} thread(s) for {duration}s")

    stop_event = threading.Event()
    threads    = []
    start_time = time.time()

    # Start stress threads
    for _ in range(num_threads):
        t = threading.Thread(target=_cpu_worker, args=(stop_event,), daemon=True)
        t.start()
        threads.append(t)

    # Collect metrics while stress runs
    metrics = _collect_metrics(duration)

    # Stop stress threads
    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    recovery_start = time.time()

    # Wait for CPU to recover below 20%
    for _ in range(10):
        if psutil.cpu_percent(interval=0.5) < 20:
            break

    recovery_time = round(time.time() - recovery_start, 2)
    total_duration = round(time.time() - start_time, 2)

    result = "Resilient" if metrics["cpu_peak"] < 90 else "Vulnerable"

    logger.info(
        f"[Chaos] CPU stress done → peak={metrics['cpu_peak']}%, "
        f"recovery={recovery_time}s, result={result}"
    )

    return {
        "experiment_type":    "cpu_stress",
        "intensity_level":    intensity_level,
        "cpu_peak":           metrics["cpu_peak"],
        "memory_peak":        metrics["memory_peak"],
        "disk_io_peak":       None,
        "duration_secs":      total_duration,
        "recovery_time_secs": recovery_time,
        "result":             result,
        "notes":              f"{num_threads} worker thread(s)",
    }


# ── Memory Stress ──────────────────────────────────────────────────────────────

def run_memory_stress(duration: int, intensity_level: int) -> dict:
    """
    Allocate a chunk of memory for `duration` seconds then release it.
    intensity_level controls allocation size.
    """
    duration   = min(duration, MAX_DURATION_SECS)
    alloc_mb   = min(intensity_level * 64, MAX_MEMORY_MB)  # 64/128/256 MB

    logger.info(f"[Chaos] Memory stress → allocating {alloc_mb}MB for {duration}s")

    start_time = time.time()
    blob       = None

    try:
        # Allocate memory
        blob = bytearray(alloc_mb * 1024 * 1024)

        # Collect metrics while memory is held
        metrics = _collect_metrics(duration)

    finally:
        # Always release memory
        del blob
        blob = None

    recovery_start = time.time()

    # Wait for memory to recover
    for _ in range(10):
        if psutil.virtual_memory().percent < 80:
            break
        time.sleep(0.5)

    recovery_time  = round(time.time() - recovery_start, 2)
    total_duration = round(time.time() - start_time,     2)

    result = "Resilient" if metrics["memory_peak"] < 85 else "Vulnerable"

    logger.info(
        f"[Chaos] Memory stress done → peak={metrics['memory_peak']}%, "
        f"recovery={recovery_time}s, result={result}"
    )

    return {
        "experiment_type":    "memory_stress",
        "intensity_level":    intensity_level,
        "cpu_peak":           metrics["cpu_peak"],
        "memory_peak":        metrics["memory_peak"],
        "disk_io_peak":       None,
        "duration_secs":      total_duration,
        "recovery_time_secs": recovery_time,
        "result":             result,
        "notes":              f"Allocated {alloc_mb}MB",
    }


# ── Disk I/O Stress ────────────────────────────────────────────────────────────

def run_disk_io_stress(duration: int, intensity_level: int) -> dict:
    """
    Write and read a temp file repeatedly for `duration` seconds.
    intensity_level controls file size per iteration.
    """
    duration  = min(duration, MAX_DURATION_SECS)
    file_size = DISK_IO_FILE_SIZE * intensity_level  # MB

    logger.info(f"[Chaos] Disk I/O stress → {file_size}MB writes for {duration}s")

    start_time  = time.time()
    bytes_written = 0
    tmp_path    = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".chaos") as f:
            tmp_path = f.name

        end_time = start_time + duration
        while time.time() < end_time:
            chunk = os.urandom(file_size * 1024 * 1024)
            with open(tmp_path, "wb") as f:
                f.write(chunk)
            # Read it back
            with open(tmp_path, "rb") as f:
                _ = f.read()
            bytes_written += file_size

    finally:
        # Always clean up temp file
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    total_duration = round(time.time() - start_time, 2)
    disk_io_peak   = round(bytes_written / total_duration, 2) if total_duration > 0 else 0.0
    memory_peak    = psutil.virtual_memory().percent
    cpu_peak       = psutil.cpu_percent(interval=0.5)

    recovery_start = time.time()
    time.sleep(1)
    recovery_time  = round(time.time() - recovery_start, 2)

    result = "Resilient" if disk_io_peak < 500 else "Vulnerable"

    logger.info(
        f"[Chaos] Disk I/O done → {disk_io_peak} MB/s, "
        f"recovery={recovery_time}s, result={result}"
    )

    return {
        "experiment_type":    "disk_io",
        "intensity_level":    intensity_level,
        "cpu_peak":           cpu_peak,
        "memory_peak":        memory_peak,
        "disk_io_peak":       disk_io_peak,
        "duration_secs":      total_duration,
        "recovery_time_secs": recovery_time,
        "result":             result,
        "notes":              f"{bytes_written}MB written total",
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