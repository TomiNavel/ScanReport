# ScanReport

**ScanReport** es una aplicación web de análisis de seguridad para dominios e IPs. Permite generar informes PDF automatizados usando herramientas como Shodan, WhatWeb y WPScan.

## Características

- Análisis de dominios e IPs públicos
- Generación de informes PDF
- Panel de administración en Django
- API para generar informes desde otras aplicaciones
- Frontend integrado con Django Templates
- Despliegue sencillo con Docker

## Requisitos

- Python 3.13+
- Docker y Docker Compose (opcional para despliegue)
- Clave API de [Shodan](https://www.shodan.io/)
- Herramientas externas instaladas (WPScan, WhatWeb, etc.)

## Instalación

### 1. Clona el repositorio

```bash
git clone https://github.com/TomiNavel/scanreport.git
cd scanreport
```

### 2. Configura las variables de entorno

Crea un archivo `.env`:

```env
SECRET_KEY=clave-secreta
SHODAN_API_KEY=tu-api-key
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
```

### 3. Instala dependencias

```bash
pip install -r requirements.txt
```

### 4. Ejecuta el servidor de desarrollo

```bash
python manage.py migrate
python manage.py runserver
```

### 5. Accede a la aplicación

Abre tu navegador en `http://127.0.0.1:8000`.

---

## Uso

1. Inicia sesión en `/login/`
2. Introduce un dominio o IP en el formulario principal
3. Genera y descarga el informe PDF desde la vista de resultados

---

## Docker

Para ejecutar la aplicación con Docker:

```bash
docker-compose up --build
```

---

## Estructura del proyecto

```plaintext
core/             → Configuración del proyecto Django
main/             → Página principal
login/            → Gestión de usuarios
servicios/        → Servicios de análisis (IP/Dominio)
reports/          → Generación y plantillas de informes
media/            → PDFs generados (ignorado por git)
static/           → CSS y JS
```

