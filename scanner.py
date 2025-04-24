import ipaddress
import subprocess
import socket
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor

# Configuración
TIEMPO_ESPERA = 7  # Segundos mínimo que debe durar el análisis
PUERTOS_ESCANEAR = [22, 80, 443, 135]  # Puertos específicos a escanear

# Diccionario de puertos y posibles sistemas operativos
SERVICIOS = {
    22: {"nombre": "SSH", "sistemas": ["Linux", "Unix", "Router"]},
    80: {"nombre": "HTTP", "sistemas": ["Cualquier SO"]},
    443: {"nombre": "HTTPS", "sistemas": ["Cualquier SO"]},
    135: {"nombre": "RPC", "sistemas": ["Windows"]}
}

# Patrones para detección de SO
PATRONES_SO = {
    "Windows": [r"Windows", r"Microsoft"],
    "Linux": [r"Linux", r"Ubuntu", r"Debian", r"CentOS"],
    "Router": [r"Cisco", r"RouterOS", r"TP-Link"],
    "IoT": [r"Embedded", r"Camera", r"Printer"]
}

log_resultados = []

def obtener_ip_local():
    """Obtiene la IP local de la máquina."""
    try:
        hostname = socket.gethostname()
        ip_local = socket.gethostbyname(hostname)
        return ip_local
    except Exception as e:
        print(f"[!] Error al obtener IP local: {e}")
        return None

def validar_formato_ip(ip_str):
    """Valida si una cadena tiene formato IPv4 válido."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False

def validar_red_cidr(red_cidr):
    """Valida exhaustivamente la red en formato CIDR."""
    try:
        # Verificar formato básico
        if "/" not in red_cidr:
            print("\n[!] Error: Formato incorrecto. Debe ser IPv4/Prefijo (ej: x.x.x.x/xx)")
            return False
        
        ip_str, prefijo_str = red_cidr.split("/", 1)
        
        # Validar IPv4
        if not validar_formato_ip(ip_str):
            print(f"\n[!] Error: IPv4 '{ip_str}' no válida")
            return False
        
        # Validar prefijo
        try:
            prefijo = int(prefijo_str)
            if not (0 <= prefijo <= 32):
                print(f"\n[!] Error: Prefijo {prefijo} no válido (debe ser 0-32)")
                return False
        except ValueError:
            print(f"\n[!] Error: Prefijo '{prefijo_str}' no es un número válido")
            return False
        
        # Validar red completa
        try:
            red = ipaddress.ip_network(red_cidr, strict=True)
            return True
        except ValueError as e:
            print(f"\n[!] Error en la red CIDR: {e}")
            return False
            
    except Exception as e:
        print(f"\n[!] Error inesperado al validar la red: {e}")
        return False

def ping_individual(ip):
    """Realiza ping a una IP individual (optimizado para Windows)."""
    try:
        resultado = subprocess.run(["ping", "-n", "1", "-w", "300", str(ip)],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True)
        
        mensaje = ""
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

def ping_sweep(red_cidr):
    """Realiza barrido de red con ping."""
    inicio = time.time()
    red = ipaddress.ip_network(red_cidr, strict=False)
    print(f"\n[+] Escaneando red: {red_cidr}...\n")
    log_resultados.append(f"Escaneando red: {red_cidr}...")

    activos = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        resultados = list(executor.map(ping_individual, red.hosts()))
        activos = [ip for ip in resultados if ip]

    # Asegurar que el escaneo dure al menos TIEMPO_ESPERA segundos
    tiempo_transcurrido = time.time() - inicio
    if tiempo_transcurrido < TIEMPO_ESPERA:
        time.sleep(TIEMPO_ESPERA - tiempo_transcurrido)
    
    return activos

def detectar_sistema_operativo(host, puertos_abiertos):
    """Intenta determinar el sistema operativo basado en puertos abiertos y banners."""
    posibles_so = set()
    
    # Primera pasada: Ver por puertos conocidos
    for puerto in puertos_abiertos:
        if puerto in SERVICIOS:
            posibles_so.update(SERVICIOS[puerto]["sistemas"])
    
    # Segunda pasada: Intentar obtener banners para mayor precisión
    banners = []
    for puerto in puertos_abiertos:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((host, puerto))
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    banners.append(banner)
                    for so, patrones in PATRONES_SO.items():
                        for patron in patrones:
                            if re.search(patron, banner, re.IGNORECASE):
                                posibles_so.add(so)
        except:
            continue
    
    # Tercera pasada: Analizar TTL (aproximación básica)
    try:
        ttl = obtener_ttl(host)
        if ttl:
            if 64 <= ttl <= 128:  # Típico de Linux/Unix
                posibles_so.add("Linux/Unix")
            elif ttl <= 64:  # Típico de routers/equipos de red
                posibles_so.add("Router/Embedded")
            elif ttl >= 128:  # Típico de Windows
                posibles_so.add("Windows")
    except:
        pass
    
    if not posibles_so:
        return "Desconocido"
    
    # Priorizar detecciones más específicas
    if "Windows" in posibles_so and len(posibles_so) > 1:
        posibles_so.remove("Cualquier SO")
    
    return ", ".join(sorted(posibles_so))

def obtener_ttl(host):
    """Intenta obtener el TTL mediante ping para ayudar a identificar el SO."""
    try:
        resultado = subprocess.run(["ping", "-n", "1", "-w", "300", host],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True)
        
        if resultado.returncode == 0:
            salida = resultado.stdout
            match = re.search(r"TTL=(\d+)", salida)
            if match:
                return int(match.group(1))
    except:
        pass
    return None

def escanear_puerto(host, puerto):
    """Escanea un puerto individual y obtiene banner si está abierto."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            resultado = s.connect_ex((host, puerto))
            servicio = SERVICIOS.get(puerto, {}).get("nombre", f"Puerto {puerto}")
            
            if resultado == 0:
                banner = ""
                try:
                    if puerto == 80 or puerto == 443:
                        s.send(b"GET / HTTP/1.1\r\nHost: %b\r\n\r\n" % host.encode())
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                except:
                    pass
                
                mensaje = f"  [✓] {servicio} ({puerto}) abierto"
                if banner:
                    mensaje += f" → Banner: {banner[:50]}"  # Limitar longitud del banner
                
                print(mensaje)
                log_resultados.append(mensaje)
                return puerto
            else:
                mensaje = f"  [✗] {servicio} ({puerto}) cerrado"
                print(mensaje)
                log_resultados.append(mensaje)
                return None
    except Exception as e:
        mensaje = f"[✗] Error al escanear {host}:{puerto} - {str(e)}"
        print(mensaje)
        log_resultados.append(mensaje)
        return None

def escanear_puertos(host, puertos):
    """Escanea múltiples puertos en paralelo."""
    print(f"\n[+] Escaneando puertos en {host}...")
    log_resultados.append(f"Escaneando puertos en {host}...")
    
    inicio = time.time()
    abiertos = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        resultados = list(executor.map(lambda p: escanear_puerto(host, p), puertos))
        abiertos = [p for p in resultados if p is not None]
    
    # Asegurar tiempo mínimo de escaneo
    tiempo_transcurrido = time.time() - inicio
    if tiempo_transcurrido < TIEMPO_ESPERA/2:  # Mitad del tiempo total
        time.sleep((TIEMPO_ESPERA/2) - tiempo_transcurrido)
    
    # Detectar sistema operativo
    if abiertos:
        so_detectado = detectar_sistema_operativo(host, abiertos)
        print(f"  [i] Sistema operativo detectado: {so_detectado}")
        log_resultados.append(f"  [i] Sistema operativo detectado: {so_detectado}")
        return abiertos, so_detectado
    
    return abiertos, "Desconocido"

def guardar_resultados(nombre_archivo="resultados_escaneo.txt"):
    """Guarda los resultados en un archivo."""
    try:
        ruta_script = os.path.dirname(os.path.abspath(__file__))
        ruta_archivo = os.path.join(ruta_script, nombre_archivo)
        
        with open(ruta_archivo, "w", encoding="utf-8") as archivo:
            for linea in log_resultados:
                archivo.write(linea + "\n")
        
        print(f"\n[✓] Resultados guardados en '{ruta_archivo}'")
    except Exception as e:
        print(f"\n[✗] Error al guardar resultados: {e}")

def main():
    print("\n=== Escáner de Red Avanzado con Detección de SO ===")
    
    # Obtener y mostrar IP local
    ip_local = obtener_ip_local()
    if ip_local:
        print(f"\n[+] Tu dirección IPv4 local es: {ip_local}")
    
    # Validar entrada de red
    while True:
        red_objetivo = input("\nIngrese la red a analizar en formato CIDR (ej. 192.168.1.0/24): ").strip()
        
        if not red_objetivo:
            print("[!] Error: No se ingresó ninguna red")
            continue
            
        if not validar_red_cidr(red_objetivo):
            continue
        
        break
    
    # Realizar escaneo
    try:
        print(f"\n[+] Iniciando análisis de la red {red_objetivo}...")
        hosts_activos = ping_sweep(red_objetivo)
        
        resumen = f"\n[+] Resumen - Hosts activos encontrados: {len(hosts_activos)}"
        print(resumen)
        log_resultados.append(resumen)
        
        if hosts_activos:
            resultados_hosts = []
            for i, host in enumerate(hosts_activos, 1):
                print(f"\n{i}. Analizando host: {host}")
                puertos_abiertos, so_detectado = escanear_puertos(host, PUERTOS_ESCANEAR)
                resumen_host = f"{host} → Puertos abiertos: {puertos_abiertos} → SO: {so_detectado}"
                print(resumen_host)
                log_resultados.append(resumen_host)
                resultados_hosts.append(resumen_host)
            
            # Mostrar resumen final
            print("\n[+] Resumen detallado:")
            for resultado in resultados_hosts:
                print(resultado)
        else:
            mensaje = "[!] No se encontraron hosts activos en la red."
            print(mensaje)
            log_resultados.append(mensaje)
        
        # Opción para guardar resultados
        guardar = input("\n¿Deseas guardar los resultados? (s/n): ").lower()
        if guardar == 's':
            nombre_archivo = input(f"Nombre del archivo (Enter para 'resultados_escaneo.txt'): ").strip()
            guardar_resultados(nombre_archivo if nombre_archivo else None)
            
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario")
    except Exception as e:
        print(f"\n[✗] Error durante el escaneo: {str(e)}")
    finally:
        print("\n[+] Análisis completado")

if __name__ == "__main__":
    main()
   
