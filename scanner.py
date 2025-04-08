import ipaddress
import subprocess
import socket

# Diccionario de puertos con sus nombres
puertos_nombres = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
}

# Función para hacer ping a todos los hosts de una red
def ping_sweep(red_cidr):
    red = ipaddress.ip_network(red_cidr, strict=False)
    activos = []

    print(f"Haciendo ping a la red: {red_cidr}...\n")
    for ip in red.hosts():
        ip = str(ip)
        try:
            # Forzamos un error usando una IP inválida (fuera de rango)
            if ip == "192.168.1.300":  # IP inválida para forzar un error
                raise ValueError(f"Dirección IP {ip} es inválida")
            
            # Cambia "-n" por "-c" si usas Linux o Mac
            resultado = subprocess.run(["ping", "-n", "1", "-w", "255", ip], stdout=subprocess.DEVNULL)
            if resultado.returncode == 0:
                print(f"[✓] Host activo: {ip}")
                activos.append(ip)
            else:
                print(f"[✗] Host inactivo: {ip}")
        except Exception as e:
            print(f"[✗] Error al hacer ping a {ip}: {e}")

    return activos

# Función para escanear puertos en un host
def port_scan(host, puertos):
    abiertos = []
    print(f"\nEscaneando puertos en {host}...")
    for puerto in puertos:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                resultado = s.connect_ex((host, puerto))
                if resultado == 0:
                    # Si el puerto está abierto, muestra el nombre del servicio
                    servicio = puertos_nombres.get(puerto, f"Puerto {puerto}")
                    print(f"  [✓] {servicio} (Puerto {puerto}) abierto")
                    abiertos.append(puerto)
                else:
                    servicio = puertos_nombres.get(puerto, f"Puerto {puerto}")
                    print(f"  [✗] {servicio} (Puerto {puerto}) cerrado")
        except Exception as e:
            print(f"[✗] Error al escanear el puerto {puerto} en {host}: {e}")
    return abiertos

# Programa principal
if __name__ == "__main__":
    # Realiza el escaneo solo una vez
    activos = ping_sweep("192.168.1.0/24")
    print("\nResumen de hosts activos:", activos)

    if len(activos) > 0:
        for host in activos:
            abiertos = port_scan(host, [22, 80, 443])  # Escanea puertos 22 (SSH), 80 (HTTP), 443 (HTTPS)
            print(f"{host} → Puertos abiertos: {abiertos}")
    else:
        print("No se encontraron hosts activos en la red.")
