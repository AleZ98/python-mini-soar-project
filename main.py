import time
import re
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import json

class SecuritySOARHandler(FileSystemEventHandler):
    def __init__(self, log_file_name="auth.log"):
        self.log_file_name = log_file_name
        # Dicționar în care ținem starea: { "192.168.1.50": [timestamp1, timestamp2] }
        self.failed_attempts = {}
        self.blocked_ips = set()
        
        # Setări pentru reguli (Praguri)
        self.threshold = 3
        self.time_window_minutes = 5

    def on_modified(self, event):
        # Această metodă este apelată automat de watchdog când fișierul se modifică
        if event.src_path.endswith(self.log_file_name):
            self.read_new_logs()

    def read_new_logs(self):
        # Deschidem fișierul și citim ultima linie adăugată
        try:
            with open(self.log_file_name, "r") as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    self.parse_and_evaluate(last_line)
        except Exception as e:
            print(f"[!] Erore la citirea fișierului: {e}")

    def parse_and_evaluate(self, line):
        # Extragem data, acțiunea și IP-ul folosind RegEx
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.*?) for user .*? from ([\d.]+)"
        match = re.search(pattern, line)
        
        if match:
            timestamp_str, action, ip = match.groups()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            
            # Ne interesează doar eșecurile de autentificare
            if "Failed login" in action:
                self.handle_failed_login(ip, timestamp)

    def handle_failed_login(self, ip, timestamp):
        if ip in self.blocked_ips:
            return  # Dacă e deja blocat, ignorăm

        # Inițializăm lista pentru IP dacă nu există
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []

        # Adăugăm timestamp-ul curent
        self.failed_attempts[ip].append(timestamp)

        # Curățăm încercările mai vechi decât fereastra de timp stabilită
        window_start = timestamp - timedelta(minutes=self.time_window_minutes)
        self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if t >= window_start]

        print(f"[*] IP {ip}: {len(self.failed_attempts[ip])} eșecuri înregistrate.")

        # Verificăm dacă am depășit pragul
        if len(self.failed_attempts[ip]) >= self.threshold:
            self.trigger_response(ip)

    def trigger_response(self, ip):
        self.blocked_ips.add(ip)
        print(f"\n[!] ALERTA SOAR: IP-ul {ip} a fost BLOCAT automat pentru atac de tip Brute-Force!\n")
        # Aici poți adăuga pe viitor codul care scrie într-un firewall sau trimite un webhook.

        firewall_rule = "blocked_ips.txt"
        with open(firewall_rule, "a") as f:
            f.write(f"DENY_IP: {ip} - BLOCAT la {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            print(f"[*] Regula de firewall pentru IP-ul {ip} a fost adăugată în '{firewall_rule}'.")

        incident_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": "Brute-Force Attack",
            "source_ip": ip,
            "action_taken": "Blocked and added to firewall blacklist",
            "failed_attempts": len(self.failed_attempts[ip]),
        }

        report_file_name = f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file_name, "w") as report_file:
            json.dump(incident_data, report_file, indent=4)
        print(f"[*] Raportul incidentului a fost salvat în '{report_file_name}'.")
        
    


# --- Pornirea aplicației ---
if __name__ == "__main__":
    # Cream un fișier gol de test dacă nu există
    open("auth.log", "a").close()

    event_handler = SecuritySOARHandler("auth.log")
    observer = Observer()
    observer.schedule(event_handler, path=".", recursive=False)

    print("[*] Motorul SOAR bazat pe clase și Watchdog a pornit. Modifică fișierul 'auth.log' ca să testezi.")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
                          

        
        