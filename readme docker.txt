# Proyecto Docker – Devasc

Este txt contiene 3 aplicaciones distintas desarrolladas como parte de una evaluación de habilidades con Docker y Python dentro de la máquina virtual DEVASC.

## Requisitos
- Máquina virtual DEVASC de Cisco (formato OVA)
- Docker instalado dentro de la VM
- Python 3.x
- Editor de texto o terminal

## Proyectos

### 1. Flask IP Viewer (puerto 8000)
Aplicación básica en Flask que devuelve la IP del cliente.

### 2. Flask con HTML y CSS (puerto 8181)
Aplicación web estilizada que muestra la IP usando plantillas HTML y CSS.

### 3. Sitio Nginx con script Bash (puerto 8888)
Sitio web estático desplegado en Nginx usando un script de automatización.

## Cómo ejecutar
Cada proyecto tiene su propio Dockerfile. Solo debes entrar a la carpeta, construir la imagen y ejecutar el contenedor.

```bash
docker build -t nombrex
docker run -d -p puerto:puerto nombrex
