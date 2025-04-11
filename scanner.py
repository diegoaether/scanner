import ipaddress
import subprocess
import socket

# Diccionario de puertos con sus nombres
puertos_nombres = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
}

log_resultados = []  # Lista para almacenar resultados

# Función para guardar resultados
def guardar_resultados_en_archivo(resultados, nombre_archivo="resultados.txt"):
    with open(nombre_archivo, "w") as archivo:
        for linea in resultados:
            archivo.write(linea + "\n")

# Función para hacer ping a todos los hosts de una red
def ping_sweep(red_cidr):
    red = ipaddress.ip_network(red_cidr, strict=False)
    activos = []

    mensaje = f"Haciendo ping a la red: {red_cidr}...\n"
    print(mensaje)
    log_resultados.append(mensaje.strip())

    for ip in red.hosts():
        ip = str(ip)
        try:
            if ip == "192.168.1.300":
                raise ValueError(f"Dirección IP {ip} es inválida")
            
            resultado = subprocess.run(["ping", "-n", "1", "-w", "255", ip], stdout=subprocess.DEVNULL)
            if resultado.returncode == 0:
                mensaje = f"[✓] Host activo: {ip}"
                activos.append(ip)
            else:
                mensaje = f"[✗] Host inactivo: {ip}"
        except Exception as e:
            mensaje = f"[✗] Error al hacer ping a {ip}: {e}"

        print(mensaje)
        log_resultados.append(mensaje)

    return activos

# Función para escanear puertos en un host
def port_scan(host, puertos):
    abiertos = []
    mensaje = f"\nEscaneando puertos en {host}..."
    print(mensaje)
    log_resultados.append(mensaje.strip())

    for puerto in puertos:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                resultado = s.connect_ex((host, puerto))
                servicio = puertos_nombres.get(puerto, f"Puerto {puerto}")
                if resultado == 0:
                    mensaje = f"  [✓] {servicio} (Puerto {puerto}) abierto"
                    abiertos.append(puerto)
                else:
                    mensaje = f"  [✗] {servicio} (Puerto {puerto}) cerrado"
        except Exception as e:
            mensaje = f"[✗] Error al escanear el puerto {puerto} en {host}: {e}"

        print(mensaje)
        log_resultados.append(mensaje)

    return abiertos

# Programa principal
if __name__ == "__main__":
    activos = ping_sweep("192.168.1.0/24")
    resumen = f"\nResumen de hosts activos: {activos}"
    print(resumen)
    log_resultados.append(resumen.strip())

    if len(activos) > 0:
        for host in activos:
            abiertos = port_scan(host, [22, 80, 443])
            resumen_host = f"{host} → Puertos abiertos: {abiertos}"
            print(resumen_host)
            log_resultados.append(resumen_host)
    else:
        mensaje = "No se encontraron hosts activos en la red."
        print(mensaje)
        log_resultados.append(mensaje)

    # Preguntar si desea guardar resultados
    opcion = input("\n¿Deseas guardar los resultados en un archivo? (s/n): ").lower()
    if opcion == "s":
        nombre = input("Nombre del archivo (deja en blanco para 'resultados.txt'): ")
        if not nombre:
            nombre = "resultados.txt"
        guardar_resultados_en_archivo(log_resultados, nombre)
        print(f"✓ Resultados guardados en '{nombre}'")

