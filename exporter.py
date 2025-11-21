#!/usr/bin/env python3
from prometheus_client import start_http_server, Gauge
import subprocess
import time
import psutil
import socket

# Define services to check on host
HOST_SERVICES = {
    "mariadb": "mariadb",
    "mongodb": "mongod",
    "docker": "docker"
}
# Define services to check inside containers
CONTAINER_SERVICES = {
    "nginx": "nginx",
    "php_fpm": "php-fpm"
}

# Disk I/O processes mapping
DISK_IO_PROCESSES = {
    "mariadb": "mariadbd",
    "mongodb": "mongod",
    "docker": "dockerd"
}

# Prometheus metrics
service_status = Gauge(
    "service_running_status",
    "Service running status (1=running, 0=stopped, -1=unhealthy)",
    ["service", "hostname"]
)
service_cpu = Gauge(
    "service_cpu_usage_percent",
    "Service CPU usage percent",
    ["service"]
)
service_mem = Gauge(
    "service_memory_usage_mb",
    "Service memory usage in MB",
    ["service"]
)
service_disk_read = Gauge(
    "service_disk_read_bytes",
    "Service disk read bytes",
    ["service"]
)
service_disk_write = Gauge(
    "service_disk_write_bytes",
    "Service disk write bytes",
    ["service"]
)
# New metrics for portal/api port and curl health
portal_listen_status = Gauge("portal_listen_status", "Portal port 443 listen status")
api_listen_status = Gauge("api_listen_status", "API port 8443 listen status")
portal_curl_status = Gauge("portal_curl_status", "Portal curl health status")
api_curl_status = Gauge("api_curl_status", "API curl health status")

def check_host_service(process_name):
    """Check service status using systemctl and process status using psutil."""
    status = -1

    # Check service status with systemctl
    try:
        result = subprocess.run(
            ["systemctl", "is-active", process_name],
            capture_output=True, text=True, timeout=5
        )
        status_str = result.stdout.strip()
        if status_str == "active":
            status = 1
        elif status_str == "inactive":
            status = 0
        else:
            status = -1
    except Exception:
        status = -1

    # Check for unhealthy process states and get resource usage
    cpu, mem, read_bytes, write_bytes = None, None, None, None
    for proc in psutil.process_iter(['name', 'status']):
        if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
            # Unhealthy states: zombie, stopped, uninterruptible sleep
            if proc.info['status'] in (
                psutil.STATUS_ZOMBIE,      # Z
                psutil.STATUS_STOPPED,     # T
                psutil.STATUS_DISK_SLEEP   # D
            ):
                status = -1
            try:
                cpu = proc.cpu_percent(interval=0.1)
                mem = proc.memory_info().rss / (1024 * 1024)  # MB
                io = proc.io_counters()
                read_bytes = io.read_bytes if io else 0
                write_bytes = io.write_bytes if io else 0
            except Exception:
                cpu, mem, read_bytes, write_bytes = None, None, None, None
            break

    return status, cpu, mem, read_bytes, write_bytes

def get_container_ids():
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}"],
            capture_output=True, text=True
        )
        return result.stdout.strip().split("\n") if result.stdout.strip() else []
    except Exception as e:
        print(f"Error fetching containers: {e}")
        return []

def get_container_names():
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}} {{.Names}}"],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split("\n")
        return {line.split()[0]: line.split()[1] for line in lines if line}
    except Exception as e:
        print(f"Error fetching container names: {e}")
        return {}

def check_container_service(container_id, service_name, process_name):
    """
    For nginx: use service status.
    For php-fpm: use ps aux and STAT column.
    """
    status = -1

    if service_name == "nginx":
        # Check service status using 'service <service> status'
        try:
            svc_cmd = ["docker", "exec", container_id, "service", service_name, "status"]
            svc_result = subprocess.run(svc_cmd, capture_output=True, text=True, timeout=5)
            if "running" in svc_result.stdout or "active (running)" in svc_result.stdout:
                status = 1
            elif "inactive" in svc_result.stdout or "stopped" in svc_result.stdout:
                status = 0
            else:
                status = -1
        except Exception:
            status = -1

        # Check process status using ps aux
        try:
            ps_cmd = ["docker", "exec", container_id, "ps", "aux"]
            ps_result = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=5)
            for line in ps_result.stdout.splitlines():
                if process_name in line:
                    parts = line.split()
                    if len(parts) > 7:
                        stat = parts[7]
                        if any(flag in stat for flag in ['T', 'Z', 'D']):
                            status = -1
                    break
        except Exception:
            pass

    elif service_name == "php_fpm":
        # Only use ps aux for php-fpm
        try:
            ps_cmd = ["docker", "exec", container_id, "ps", "aux"]
            ps_result = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=5)
            found = False
            for line in ps_result.stdout.splitlines():
                if process_name in line:
                    found = True
                    parts = line.split()
                    if len(parts) > 7:
                        stat = parts[7]
                        if any(flag in stat for flag in ['T', 'Z', 'D']):
                            status = -1
                        else:
                            status = 1
                    break
            if not found:
                status = 0
        except Exception:
            status = -1

    else:
        # Default: try service status, fallback to ps aux
        try:
            svc_cmd = ["docker", "exec", container_id, "service", service_name, "status"]
            svc_result = subprocess.run(svc_cmd, capture_output=True, text=True, timeout=5)
            if "running" in svc_result.stdout or "active (running)" in svc_result.stdout:
                status = 1
            elif "inactive" in svc_result.stdout or "stopped" in svc_result.stdout:
                status = 0
            else:
                status = -1
        except Exception:
            status = -1

    return status

def get_container_resource_usage():
    """Get CPU and memory usage for all running containers."""
    usage = {}
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}} {{.MemUsage}}"],
            capture_output=True, text=True
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split()
            name = parts[0]
            cpu = float(parts[1].replace('%', ''))
            mem_str = parts[2]
            # mem_str example: "12.34MiB/1GiB"
            mem_mb = 0.0
            if 'MiB' in mem_str:
                mem_mb = float(mem_str.split('MiB')[0])
            elif 'GiB' in mem_str:
                mem_mb = float(mem_str.split('GiB')[0]) * 1024
            usage[name] = (cpu, mem_mb)
    except Exception as e:
        print(f"Error getting container resource usage: {e}")
    return usage

def check_port_listen(port):
    """Return 1 if port is listening, else 0."""
    try:
        result = subprocess.run(
            ["ss", "-tulnp"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            if f":{port} " in line and "LISTEN" in line:
                return 1
        return 0
    except Exception:
        return 0

def check_curl_health(port):
    """
    Returns:
      1 if HTTP response received,
      -1 if SSL error,
      0 if connection refused or other error.
    """
    try:
        result = subprocess.run(
            ["curl", f"https://localhost:{port}", "--insecure", "--max-time", "5"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return 1
        elif "SSL:" in result.stderr:
            return -1
        elif "Connection refused" in result.stderr:
            return 0
        else:
            return 0
    except Exception:
        return 0

def get_host_disk_io(process_name):
    read_bytes, write_bytes = None, None
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
            try:
                io = proc.io_counters()
                read_bytes = io.read_bytes / (1024 * 1024) if io else 0
                write_bytes = io.write_bytes / (1024 * 1024) if io else 0
            except Exception:
                read_bytes, write_bytes = None, None
            break
    return read_bytes, write_bytes

def get_container_disk_io(container_id, process_name):
    try:
        # Get PID of the process inside the container
        ps_cmd = ["docker", "exec", container_id, "ps", "-eo", "pid,comm"]
        result = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if process_name in line:
                parts = line.split()
                if len(parts) >= 2:
                    pid = parts[0]
                    # Read /proc/<pid>/io
                    io_cmd = ["docker", "exec", container_id, "cat", f"/proc/{pid}/io"]
                    io_result = subprocess.run(io_cmd, capture_output=True, text=True, timeout=5)
                    read_bytes, write_bytes = 0, 0
                    for io_line in io_result.stdout.splitlines():
                        if io_line.startswith("read_bytes:"):
                            read_bytes = int(io_line.split()[1]) / (1024 * 1024)
                        if io_line.startswith("write_bytes:"):
                            write_bytes = int(io_line.split()[1]) / (1024 * 1024)
                    return read_bytes, write_bytes
        return None, None
    except Exception:
        return None, None

def update_metrics():
    hostname = socket.gethostname()
    # Host services
    for name, process in HOST_SERVICES.items():
        status, cpu, mem, read_bytes, write_bytes = check_host_service(process)
        service_status.labels(service=name, hostname=hostname).set(status)
        if cpu is not None:
            service_cpu.labels(service=name).set(cpu)
        if mem is not None:
            service_mem.labels(service=name).set(mem)
        if read_bytes is not None:
            service_disk_read.labels(service=name).set(read_bytes / (1024 * 1024))  # MB
        if write_bytes is not None:
            service_disk_write.labels(service=name).set(write_bytes / (1024 * 1024))  # MB

    # Container services (nginx, php-fpm) per container
    container_names = get_container_names()
    for svc_name, process in CONTAINER_SERVICES.items():
        for cid, cname in container_names.items():
            status = check_container_service(cid, svc_name, process)
            service_status.labels(service=svc_name, hostname=cname).set(status)

    # Expose resource usage for all running containers
    container_usage = get_container_resource_usage()
    for cname, (cpu, mem) in container_usage.items():
        service_cpu.labels(service=f"container_{cname}").set(cpu)
        service_mem.labels(service=f"container_{cname}").set(mem)

    # Portal port/curl health
    portal_listen_status.set(check_port_listen(443))
    portal_curl_status.set(check_curl_health(443))

    # API port/curl health
    api_listen_status.set(check_port_listen(8443))
    api_curl_status.set(check_curl_health(8443))

if __name__ == "__main__":
    start_http_server(9105)
    print("Service status exporter running on port 9105...")
    while True:
        update_metrics()
        time.sleep(10)
