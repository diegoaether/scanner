import ipaddress
import subprocess
import socket
import os
from concurrent.futures import ThreadPoolExecutor

# Diccionario de puertos conocidos
puertos_nombres = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    135: "RPC"  # Añadido el puerto 135 para RPC
}

log_resultados = []

def obtener_ip_local():
    """Obtiene la IP local de la máquina."""
    hostname = socket.gethostname()
    ip_local = socket.gethostbyname(hostname)
    return ip_local

def guardar_resultados_en_archivo(resultados, nombre_archivo="resultados.txt"):
    with open(nombre_archivo, "w", encoding="utf-8") as archivo:
        for linea in resultados:
            archivo.write(linea + "\n")

# Ping a una IP individual (función auxiliar para paralelismo)
def ping_individual(ip):
    try:
        resultado = subprocess.run(["ping", "-n", "1", "-w", "300", str(ip)],
                                   stdout=subprocess.DEVNULL)
        if resultado.returncode == 0:
            mensaje = f"[✓] Host activo: {ip}"
            log_resultados.append(mensaje)
            print(mensaje)
            return str(ip)
        else:
            mensaje = f"[✗] Host inactivo: {ip}"
    except Exception as e:
        mensaje = f"[✗] Error al hacer ping a {ip}: {e}"

    log_resultados.append(mensaje)
    print(mensaje)
    return None

# Barrido de red optimizado (ping sweep paralelo)
def ping_sweep(red_cidr):
    red = ipaddress.ip_network(red_cidr, strict=False)
    print(f"\nHaciendo ping a la red: {red_cidr}...\n")
    log_resultados.append(f"Haciendo ping a la red: {red_cidr}...")

    activos = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        resultados = executor.map(ping_individual, red.hosts())
        activos = [ip for ip in resultados if ip]

    return activos

# Escaneo de puertos con banner grabbing
def port_scan(host, puertos):
    abiertos = []
    print(f"\nEscaneando puertos en {host}...")
    log_resultados.append(f"Escaneando puertos en {host}...")

    def escanear_puerto(puerto):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                resultado = s.connect_ex((host, puerto))
                servicio = puertos_nombres.get(puerto, f"Puerto {puerto}")
                mensaje = ""
                if resultado == 0:
                    mensaje = f"  [✓] {servicio} (Puerto {puerto}) abierto"
                    abiertos.append(puerto)
                    try:
                        banner = s.recv(1024).decode("utf-8").strip()
                        if banner:
                            mensaje += f" → Banner: {banner}"
                    except:
                        pass
                else:
                    mensaje = f"  [✗] {servicio} (Puerto {puerto}) cerrado"
        except Exception as e:
            mensaje = f"[✗] Error al escanear el puerto {puerto} en {host}: {e}"

        print(mensaje)
        log_resultados.append(mensaje)

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(escanear_puerto, puertos)

    return abiertos

# Validación de la red ingresada
def validar_red(red_cidr):
    try:
        # Verifica si la red tiene formato CIDR válido
        if "/" not in red_cidr:
            print("\n¡Error! Debes ingresar la red en formato CIDR (por ejemplo: 192.168.83.0/24).")
            return False

        # Verifica si el prefijo está correcto (debería ser /24 como tu ejemplo)
        red = ipaddress.ip_network(red_cidr, strict=False)
        prefijo = red.prefixlen
        ip_local = obtener_ip_local()

        # Verifica si el prefijo es el adecuado
        if prefijo != 24:
            print(f"\n¡Error! El prefijo debe ser /24. El prefijo proporcionado es /{prefijo}.")
            return False

        # Verifica si la IP local está dentro de la red proporcionada
        if ipaddress.ip_address(ip_local) not in red.hosts():
            print(f"\n¡Error! Tu IP local {ip_local} no está dentro de la red proporcionada.")
            return False

        return True
    except ValueError:
        print(f"\n¡Error! La red ingresada {red_cidr} no es válida. Asegúrate de ingresar una IP válida.")
        return False

# Programa principal
if __name__ == "__main__":
    while True:
        red_objetivo = input("Introduce la red a analizar en formato CIDR: ")  # Ejemplo eliminado
        if validar_red(red_objetivo):
            break  # Si la red es válida, continúa con el análisis
    
    activos = ping_sweep(red_objetivo)

    resumen = f"\nResumen de hosts activos: {activos}"
    print(resumen)
    log_resultados.append(resumen.strip())

    if activos:
        for host in activos:
            # Ahora incluye el puerto 135 junto con los otros puertos (22, 80, 443)
            abiertos = port_scan(host, [22, 80, 443, 135])
            resumen_host = f"{host} → Puertos abiertos: {abiertos}"
            print(resumen_host)
            log_resultados.append(resumen_host)
    else:
        mensaje = "No se encontraron hosts activos en la red."
        print(mensaje)
        log_resultados.append(mensaje)

    # Guardar resultados si el usuario desea
    opcion = input("\n¿Deseas guardar los resultados en un archivo? (s/n): ").lower()
    if opcion == "s":
        nombre = input("Nombre del archivo (deja en blanco para 'resultados.txt'): ").strip()
        if not nombre:
            nombre = "resultados.txt"

        ruta_script = os.path.dirname(os.path.abspath(__file__))
        ruta_archivo = os.path.join(ruta_script, nombre)

        guardar_resultados_en_archivo(log_resultados, ruta_archivo)
        print(f"✓ Resultados guardados en '{ruta_archivo}'")
