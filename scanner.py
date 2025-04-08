import subprocess

def esta_vivo(ip):
    try:
        resultado = subprocess.check_output(["ping", "-n", "1", ip])
        return True
    except:
        return False

# Rango de IPs que vamos a escanear
base_ip = "192.168.1."  # Parte común
for i in range(1, 20):  # Del 1 al 10
    ip = base_ip + str(i)
    if esta_vivo(ip):
        print(f"✅ La computadora {ip} está activa.")
    else:
        print(f"❌ La computadora {ip} no respondió.")