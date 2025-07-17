import psutil


# Black list of shady process names

suspicious_names = ['backdoor.exe', 'rat.exe', 'meterpreter', 'cmd.exe', 'powershell.exe']


def detect_suspicious_processes():
    flagged = []