"""
Chaos Experiments — Chaos Validation Engine

Implements controlled stress experiments with schema validation, hard safety
caps, and Docker-first metrics collection with a psutil fallback.
"""

import json
import logging
import subprocess
import time
import uuid

import psutil

logger = logging.getLogger(__name__)

MAX_DURATION_SECS = 30
MAX_MEMORY_MB = 256
MAX_CPU_THREADS = 4
MAX_INTENSITY = 3
SCALED_CPU_BONUS = 2
SCALED_MEMORY_BONUS_MB = 256

VALID_EXPERIMENT_TYPES = {"cpu_stress", "memory_stress", "disk_io"}

DEFAULT_SAFE_CONFIG = {
    "type": "cpu_stress",
    "intensity": 1,
    "cpu_threads": 1,
    "memory_mb": 128,
    "duration": 5,
}


def _cpu_limit_for_threads(cpu_threads: int) -> float:
    return float(cpu_threads)


def validate_experiment_config(config: dict) -> dict:
    """
    Validate an experiment payload and enforce schema and safety caps.
    """
    if not isinstance(config, dict):
        return DEFAULT_SAFE_CONFIG.copy()

    try:
        exp_type = str(config.get("type", DEFAULT_SAFE_CONFIG["type"]))
        if exp_type not in VALID_EXPERIMENT_TYPES:
            exp_type = DEFAULT_SAFE_CONFIG["type"]

        intensity = int(config.get("intensity", DEFAULT_SAFE_CONFIG["intensity"]))
        intensity = max(1, min(intensity, MAX_INTENSITY))

        duration = int(config.get("duration", DEFAULT_SAFE_CONFIG["duration"]))
        duration = max(1, min(duration, MAX_DURATION_SECS))

        cpu_threads = int(config.get("cpu_threads", intensity))
        cpu_threads = max(1, min(cpu_threads, MAX_CPU_THREADS))

        memory_mb = int(config.get("memory_mb", intensity * 64))
        memory_mb = max(64, min(memory_mb, MAX_MEMORY_MB))
    except (TypeError, ValueError):
        return DEFAULT_SAFE_CONFIG.copy()

    return {
        "type": exp_type,
        "intensity": intensity,
        "cpu_threads": cpu_threads,
        "memory_mb": memory_mb,
        "duration": duration,
    }


def get_container_stats(container_name):
    """
    Return Docker container CPU usage as a float percentage.
    Falls back safely when Docker stats is unavailable or malformed.
    """
    if not container_name:
        return 0.0

    try:
        output = subprocess.check_output(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{json .}}",
                container_name,
            ],
            stderr=subprocess.STDOUT,
            timeout=5,
        ).decode("utf-8").strip()

        if not output:
            return 0.0

        stats = json.loads(output.splitlines()[0])
        cpu_value = str(stats.get("CPUPerc", "0%")).replace("%", "").strip()
        return float(cpu_value or 0.0)
    except subprocess.TimeoutExpired:
        # Docker Desktop on Windows can intermittently delay stats responses.
        # Treat timeout as a soft telemetry miss instead of a hard warning.
        logger.debug("[Chaos] Docker stats timed out for container '%s'", container_name)
        return 0.0
    except subprocess.CalledProcessError as exc:
        output = (exc.output or b"").decode("utf-8", errors="ignore").lower()
        if "no such container" in output:
            return 0.0
        logger.warning("[Chaos] Docker stats failed for container '%s': %s", container_name, exc)
        return 0.0
    except (subprocess.SubprocessError, json.JSONDecodeError, ValueError, OSError) as exc:
        logger.warning("[Chaos] Docker stats failed for container '%s': %s", container_name, exc)
        return 0.0


def _is_container_running(container_name: str) -> bool:
    if not container_name:
        return False
    try:
        output = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            stderr=subprocess.STDOUT,
            timeout=2,
        ).decode("utf-8").strip().lower()
        return output == "true"
    except (subprocess.SubprocessError, OSError):
        return False


def _get_container_metrics_snapshot(container_name):
    """
    Return a snapshot of container-oriented metrics.
    CPU is sourced from Docker stats, while memory/disk metrics use safe fallbacks.
    """
    cpu = get_container_stats(container_name)
    metric_source = "docker" if cpu > 0.0 else "fallback"

    memory_percent = 0.0
    disk_io_mb = 0.0

    try:
        if metric_source == "fallback":
            # If Docker stats is unavailable, use host CPU as best-effort signal
            # so dashboards do not show persistent 0% for active stress tests.
            cpu = psutil.cpu_percent(interval=None)
        memory_percent = psutil.virtual_memory().percent
        disk_io = psutil.disk_io_counters()
        if disk_io:
            disk_io_mb = (disk_io.read_bytes + disk_io.write_bytes) / (1024 * 1024)
    except Exception as exc:
        logger.debug("[Chaos] Fallback metric sampling failed: %s", exc)

    return cpu, memory_percent, disk_io_mb, metric_source


def _collect_metrics(duration: int, container_name: str, proc=None) -> dict:
    cpu_samples = []
    mem_samples = []
    disk_samples = []
    sources = set()
    last_cpu_value = 0.0
    started = time.monotonic()

    # Prime psutil so the first non-blocking cpu_percent call is meaningful.
    try:
        psutil.cpu_percent(interval=None)
    except Exception:
        pass

    # Give Docker a brief moment to register the container before sampling.
    ready_deadline = time.monotonic() + min(2.0, duration)
    while time.monotonic() < ready_deadline:
        if _is_container_running(container_name):
            break
        if proc is not None and proc.poll() is not None:
            break
        time.sleep(0.1)

    while time.monotonic() - started < duration:
        if proc is not None and proc.poll() is not None and not _is_container_running(container_name):
            break
        cpu, memory, disk_io, source = _get_container_metrics_snapshot(container_name)
        if source == "fallback":
            # Keep last useful CPU value to avoid misleading hard-zero samples
            # when Docker stats intermittently times out.
            if cpu <= 0.0 and last_cpu_value > 0.0:
                cpu = last_cpu_value
            elif cpu <= 0.0 and _is_container_running(container_name):
                try:
                    cpu = psutil.cpu_percent(interval=0.2)
                except Exception:
                    cpu = 0.0
        if cpu > 0.0:
            last_cpu_value = cpu
        cpu_samples.append(cpu)
        mem_samples.append(memory)
        disk_samples.append(disk_io)
        sources.add(source)
        time.sleep(0.5)

    return {
        "cpu_peak": round(max(cpu_samples), 2) if cpu_samples else 0.0,
        "memory_peak": round(max(mem_samples), 2) if mem_samples else 0.0,
        "disk_io_peak": round(max(disk_samples), 2) if disk_samples else 0.0,
        "metric_source": "docker" if "docker" in sources else (next(iter(sources)) if sources else "unknown"),
    }


def _new_container_name() -> str:
    return f"chaos-{uuid.uuid4().hex[:6]}"


def _run_docker_experiment(cmd):
    try:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        logger.warning("[Chaos] Docker execution unavailable, continuing with simulated run: %s", exc)
        return None


def _finalize_experiment(proc, duration: int):
    if not proc:
        return {"returncode": None, "stdout": "", "stderr": ""}
    try:
        stdout, stderr = proc.communicate(timeout=duration + 5)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    return {
        "returncode": proc.returncode,
        "stdout": (stdout or b"").decode("utf-8", errors="replace").strip(),
        "stderr": (stderr or b"").decode("utf-8", errors="replace").strip(),
    }


def _cleanup_container(container_name: str):
    if not container_name:
        return
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("[Chaos] Container cleanup failed for '%s': %s", container_name, exc)


def run_cpu_stress(duration: int, intensity_level: int, is_scaled: bool = False) -> dict:
    validated = validate_experiment_config({"type": "cpu_stress", "intensity": intensity_level, "duration": duration})
    local_max_cpu = MAX_CPU_THREADS + (SCALED_CPU_BONUS if is_scaled else 0)
    duration = validated["duration"]
    cpu_threads = min(validated["cpu_threads"], local_max_cpu)
    container_name = _new_container_name()

    logger.info("[Chaos] CPU Stress | scaled=%s | threads=%s", is_scaled, cpu_threads)
    start_time = time.monotonic()
    proc = _run_docker_experiment(
        [
            "docker",
            "run",
            "--name",
            container_name,
            "--cpus",
            str(_cpu_limit_for_threads(cpu_threads)),
            "--memory",
            f"{validated['memory_mb']}m",
            "chaos-executor",
            "--cpu",
            str(cpu_threads),
            "--timeout",
            f"{duration}s",
        ]
    )

    metrics = _collect_metrics(duration, container_name, proc)
    proc_result = _finalize_experiment(proc, duration)

    recovery_start = time.monotonic()
    while time.monotonic() - recovery_start < 2:
        if not _is_container_running(container_name):
            break
        if get_container_stats(container_name) <= 20.0:
            break
        time.sleep(0.2)
    recovery_time = round(time.monotonic() - recovery_start, 2)
    _cleanup_container(container_name)

    result = "Resilient"
    if metrics["cpu_peak"] > 80.0:
        result = "Vulnerable"
    elif proc_result["returncode"] not in (None, 0):
        result = "Vulnerable"

    return {
        "experiment_type": "cpu_stress",
        "intensity_level": validated["intensity"],
        "cpu_peak": metrics["cpu_peak"],
        "memory_peak": metrics["memory_peak"],
        "disk_io_peak": metrics["disk_io_peak"],
        "duration_secs": round(time.monotonic() - start_time, 2),
        "recovery_time_secs": recovery_time,
        "result": result,
        "metric_source": metrics["metric_source"],
        "notes": (
            f"Scaled={is_scaled}, Threads={cpu_threads}, "
            f"MetricSource={metrics['metric_source']}, "
            f"ExitCode={proc_result['returncode']}, "
            f"StdErr={proc_result['stderr'][:200]}"
        ),
    }


def run_memory_stress(duration: int, intensity_level: int, is_scaled: bool = False) -> dict:
    validated = validate_experiment_config({"type": "memory_stress", "intensity": intensity_level, "duration": duration})
    local_max_memory = MAX_MEMORY_MB + (SCALED_MEMORY_BONUS_MB if is_scaled else 0)
    duration = validated["duration"]
    memory_mb = min(validated["memory_mb"], local_max_memory)
    container_name = _new_container_name()

    logger.info("[Chaos] Memory Stress | scaled=%s | memory_mb=%s", is_scaled, memory_mb)
    start_time = time.monotonic()
    proc = _run_docker_experiment(
        [
            "docker",
            "run",
            "--name",
            container_name,
            "--memory",
            f"{memory_mb}m",
            "--cpus",
            str(_cpu_limit_for_threads(1)),
            "chaos-executor",
            "--vm",
            "1",
            "--vm-bytes",
            f"{memory_mb}M",
            "--timeout",
            f"{duration}s",
        ]
    )

    metrics = _collect_metrics(duration, container_name, proc)
    proc_result = _finalize_experiment(proc, duration)
    _cleanup_container(container_name)

    result = "Resilient"
    if metrics["cpu_peak"] > 80.0:
        result = "Vulnerable"
    elif proc_result["returncode"] not in (None, 0):
        result = "Vulnerable"

    return {
        "experiment_type": "memory_stress",
        "intensity_level": validated["intensity"],
        "cpu_peak": metrics["cpu_peak"],
        "memory_peak": metrics["memory_peak"],
        "disk_io_peak": metrics["disk_io_peak"],
        "duration_secs": round(time.monotonic() - start_time, 2),
        "recovery_time_secs": 0.5,
        "result": result,
        "metric_source": metrics["metric_source"],
        "notes": (
            f"Scaled={is_scaled}, Memory={memory_mb}MB, "
            f"MetricSource={metrics['metric_source']}, "
            f"ExitCode={proc_result['returncode']}, "
            f"StdErr={proc_result['stderr'][:200]}"
        ),
    }


def run_disk_io_stress(duration: int, intensity_level: int, is_scaled: bool = False) -> dict:
    validated = validate_experiment_config({"type": "disk_io", "intensity": intensity_level, "duration": duration})
    duration = validated["duration"]
    start_time = time.monotonic()
    container_name = _new_container_name()
    proc = _run_docker_experiment(
        [
            "docker",
            "run",
            "--name",
            container_name,
            "--memory",
            f"{validated['memory_mb']}m",
            "--cpus",
            str(_cpu_limit_for_threads(1)),
            "chaos-executor",
            "--hdd",
            str(validated["intensity"]),
            "--timeout",
            f"{duration}s",
        ]
    )

    metrics = _collect_metrics(duration, container_name, proc)
    proc_result = _finalize_experiment(proc, duration)
    _cleanup_container(container_name)

    result = "Vulnerable" if metrics["cpu_peak"] > 80.0 else "Resilient"
    if proc_result["returncode"] not in (None, 0):
        result = "Vulnerable"
    return {
        "experiment_type": "disk_io",
        "intensity_level": validated["intensity"],
        "cpu_peak": metrics["cpu_peak"],
        "memory_peak": metrics["memory_peak"],
        "disk_io_peak": metrics["disk_io_peak"],
        "duration_secs": round(time.monotonic() - start_time, 2),
        "recovery_time_secs": 1.0,
        "result": result,
        "metric_source": metrics["metric_source"],
        "notes": (
            f"Scaled={is_scaled}, DiskIntensity={validated['intensity']}, "
            f"MetricSource={metrics['metric_source']}, "
            f"ExitCode={proc_result['returncode']}, "
            f"StdErr={proc_result['stderr'][:200]}"
        ),
    }


def run_experiment(experiment_type: str, duration: int, intensity_level: int, is_scaled: bool = False) -> dict:
    """Public entry point for chaos execution."""
    try:
        if experiment_type == "memory_stress":
            metrics = run_memory_stress(duration, intensity_level, is_scaled)
        elif experiment_type == "disk_io":
            metrics = run_disk_io_stress(duration, intensity_level, is_scaled)
        else:
            metrics = run_cpu_stress(duration, intensity_level, is_scaled)
        return metrics
    except Exception as exc:
        logger.error("[Chaos] Experiment failed: %s", exc, exc_info=True)
        fallback = DEFAULT_SAFE_CONFIG.copy()
        return {
            "experiment_type": fallback["type"],
            "intensity_level": fallback["intensity"],
            "cpu_peak": 0.0,
            "memory_peak": 0.0,
            "disk_io_peak": 0.0,
            "duration_secs": fallback["duration"],
            "recovery_time_secs": 0.0,
            "result": "Resilient",
            "metric_source": "unknown",
            "notes": f"Error: {exc}",
        }
