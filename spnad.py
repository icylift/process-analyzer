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
        
    
