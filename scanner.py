import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
from ipaddress import IPv4Network, ip_network, AddressValueError, NetmaskValueError
from scapy.all import sr1, IP, ICMP

# Diccionario de puertos comunes
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

# Obtener red local desde IP obtenida automáticamente
def get_local_network():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return ip_network(local_ip + '/24', strict=False)
    except Exception:
        return None

# Detección del sistema operativo por TTL
def detect_os(ip):
    ttl = None
    try:
        pkt = IP(dst=ip)/ICMP()
        reply = sr1(pkt, timeout=1, verbose=0)
        if reply:
            ttl = reply.ttl
    except Exception:
        return "OS desconocido"

    if ttl is not None:
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Dispositivo de red o BSD"
    return "OS desconocido"

# Escanear puertos con hilos
def scan_host(ip):
    host_data = {"ip": ip, "puertos": {}, "os": "OS desconocido"}
    threads = []

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                result = s.connect_ex((ip, port))
                host_data["puertos"][port] = result == 0
        except Exception:
            host_data["puertos"][port] = False

    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    host_data["os"] = detect_os(ip)
    return host_data

# Escaneo de red con límite de hilos para velocidad moderada
def scan_network(ip, mask, output):
    try:
        output.insert(tk.END, f"Escaneando red: {ip}/{mask}\n")
        output.see(tk.END)
        network = IPv4Network(f"{ip}/{mask}", strict=False)
        active_hosts = []

        lock = threading.Lock()
        semaphore = threading.Semaphore(10)  # Máximo 10 hilos simultáneos

        def check_host(host_ip):
            with semaphore:
                pkt = IP(dst=host_ip)/ICMP()
                reply = sr1(pkt, timeout=0.5, verbose=0)
                with lock:
                    if reply:
                        output.insert(tk.END, f"Host: {host_ip} - ACTIVO\n")
                        active_hosts.append(host_ip)
                    else:
                        output.insert(tk.END, f"Host: {host_ip} - NO ACTIVO\n")
                    output.see(tk.END)
                    output.update_idletasks()

        threads = []
        for host in network.hosts():
            t = threading.Thread(target=check_host, args=(str(host),))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        output.insert(tk.END, "\n--- DETALLES DE HOSTS ACTIVOS ---\n")
        output.see(tk.END)

        for host in active_hosts:
            datos = scan_host(host)
            output.insert(tk.END, f"\nHost: {host} - ACTIVO\n")
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

# Validar entrada y permisos de red
def start_scan(ip_entry, mask_entry, output):
    ip = ip_entry.get()
    mask = mask_entry.get()

    try:
        user_network = ip_network(f"{ip}/{mask}", strict=False)
        local_network = get_local_network()

        if local_network is None:
            output.insert(tk.END, "⚠️ Error: No se pudo determinar tu red local.\n")
            output.see(tk.END)
            return

        if str(user_network.network_address) != str(local_network.network_address):
            output.insert(tk.END, "⚠️ Error: La IP ingresada es incorrecta o no está permitida.\n")
            output.see(tk.END)
            return

        if str(user_network.netmask) != str(local_network.netmask):
            output.insert(tk.END, "⚠️ Error: La máscara de subred ingresada no coincide con la de tu red local.\n")
            output.see(tk.END)
            return

    except (ValueError, AddressValueError, NetmaskValueError):
        output.insert(tk.END, "⚠️ Error: Dirección IP o máscara inválida.\n")
        output.see(tk.END)
        return

    output.delete("1.0", tk.END)
    threading.Thread(target=scan_network, args=(ip, mask, output)).start()

# Interfaz gráfica
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
