import psutil


# BLACK LIST OF SHADY PROCESS NAMES

suspicious_names = ['backdoor.exe', 'rat.exe', 'meterpreter', 'cmd.exe', 'powershell.exe']


def detect_suspicious_processes():
    flagged = []
    for proc in psutil.Process_iter(['pid', 'name', 'username']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in suspicious_names:
                flagged.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return flagged

# SCAN NETWORK CONNECTIONS FOR ANOMALIES

import socket

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    
def detect_suspicious_connections():
    suspicious_conns = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.raddr and conn.status == 'ESTABLISHED':
                pid = conn.pid
                proc = psutil.Process(pid)
                ip = conn.raddr.ip
                domain = resolve_ip(ip)
                suspicious_conns.append({
                    'Process': proc.name(),
                    'pid': pid,
                    'remote_ip': ip,
                    'domain': domain
                })
        except Exception:
            continue
    return suspicious_conns


# LOGGING AND ALERTS

from datetime import datetime

def log_alert(message):
    with open("alerts.log", "a") as log_file:
        log_file.write(f"[{datetime.now()}] {message}\n")


def alert_on_findings():
    processes = detect_suspicious_processes()
    conns = detect_suspicious_connections()

    if processes:
        print("Suspicious processes found!")
        for p in processes:
            msg = f"Suspicious process: {p['name']} (PID: {p['pid']}) by {p['username']}"
            print(msg)
            log_alert(msg)

    if conns:
        print("Suspicious network connections found!")
        for c in conns:
            msg = f"Connection from {c['process']} (PID: {c['pid']}) to {c['remote_ip']} "
