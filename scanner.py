import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import time
from ipaddress import IPv4Network
import subprocess
from concurrent.futures import ThreadPoolExecutor

ports = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    80: 'HTTP',
    443: 'HTTPS',
    3389: 'RDP',
    135: 'Microsoft RPC',
    445: 'SMB'
}

def is_host_active(ip):
    try:
        result = subprocess.run(["ping", "-n", "2", "-w", "400", ip],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def detect_os(ip):
    try:
        proc = subprocess.Popen(["ping", "-n", "1", "-w", "1000", ip],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, _ = proc.communicate()
        for line in out.splitlines():
            if "TTL=" in line:
                ttl = int(line.split("TTL=")[1])
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Dispositivo de red o BSD"
    except Exception:
        pass
    return "OS desconocido"

def scan_host(ip):
    host_data = {"ip": ip, "puertos": {}}
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                host_data["puertos"][port] = result == 0
        except Exception:
            host_data["puertos"][port] = False
    host_data["os"] = detect_os(ip)
    return host_data

def check_host(host_ip):
    return host_ip if is_host_active(host_ip) else None

def scan_network(ip, mask, output):
    try:
        output.insert(tk.END, f"Escaneando red: {ip}/{mask}\n")
        output.see(tk.END)
        network = IPv4Network((ip, mask), strict=False)

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_host, str(host)): str(host) for host in network.hosts()}

        active_hosts = []
        inactive_hosts = []

        for future in futures:
            host_ip = futures[future]
            if future.result():
                output.insert(tk.END, f"Host: {host_ip} - ACTIVO\n")
                active_hosts.append(host_ip)
            else:
                output.insert(tk.END, f"Host: {host_ip} - NO ACTIVO\n")
                inactive_hosts.append(host_ip)
            output.see(tk.END)
            output.update_idletasks()
            time.sleep(0.03)  # ← Pausa para dar tiempo a visualizar

        output.insert(tk.END, "\n--- DETALLES DE HOSTS ACTIVOS ---\n")
        output.see(tk.END)

        for host in active_hosts:
            output.insert(tk.END, f"\nHost: {host} - ACTIVO\n")
            datos = scan_host(host)
            for port, disponible in datos["puertos"].items():
                estado = "Puerto activo" if disponible else "Puerto no disponible"
                output.insert(tk.END, f"{ports[port]} ({port}) - {estado}\n")
            output.insert(tk.END, f"OS - {datos['os']}\n")
            output.see(tk.END)
            output.update_idletasks()

        output.insert(tk.END, "\nEscaneo finalizado.\n")
        output.see(tk.END)

    except Exception as e:
        output.insert(tk.END, f"Error en el escaneo: {e}\n")
        output.see(tk.END)

def start_scan(ip_entry, mask_entry, output):
    ip = ip_entry.get()
    mask = mask_entry.get()
    output.delete("1.0", tk.END)
    threading.Thread(target=scan_network, args=(ip, mask, output)).start()

def main_gui():
    window = tk.Tk()
    window.title("Escáner de Red")
    window.geometry("750x520")

    frame = tk.Frame(window)
    frame.pack(pady=10)

    tk.Label(frame, text="Dirección IP:").grid(row=0, column=0, sticky="e")
    ip_entry = tk.Entry(frame, width=20)
    ip_entry.grid(row=0, column=1, padx=5)

    tk.Label(frame, text="Máscara de subred:").grid(row=1, column=0, sticky="e")
    mask_entry = tk.Entry(frame, width=20)
    mask_entry.grid(row=1, column=1, padx=5)

    scan_button = tk.Button(frame, text="Scanner", command=lambda: start_scan(ip_entry, mask_entry, output),
                            bg="#4CAF50", fg="white", padx=10, pady=5)
    scan_button.grid(row=0, column=2, rowspan=2, padx=10, pady=5)

    output = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=90, height=25)
    output.pack(padx=10, pady=10)

    window.mainloop()

main_gui()

   
