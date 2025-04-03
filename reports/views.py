import os
import shodan
import subprocess
import pdfkit
import re
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.views.decorators.http import require_POST
from datetime import datetime
from django.conf import settings
from django.templatetags.static import static
from django.contrib import messages
from django.urls import reverse


def convert_datetimes_to_strings(data):
    """Recorre un diccionario y convierte todos los valores de tipo datetime a cadenas."""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(value, list):
                data[key] = [convert_datetimes_to_strings(item) if isinstance(item, dict) else item for item in value]
    return data


@login_required
@require_POST
def generar_pdf_shodan(request):
    ip = request.POST.get('query')
    api = shodan.Shodan(settings.SHODAN_API_KEY)

    try:
        resultados = api.host(ip)

        # Verificar si 'resultados' es un diccionario
        if not isinstance(resultados, dict):
            raise TypeError(f"Se esperaba un diccionario, pero 'resultados' es de tipo {type(resultados)}")

        datos_ip = {
            "ip_str": resultados.get('ip_str', 'N/A'),
            "hostnames": resultados.get('hostnames', []),
            "isp": resultados.get('isp', 'N/A'),
            "org": resultados.get('org', 'N/A'),
            "country_name": resultados.get('country_name', 'N/A'),
            "city": resultados.get('city', 'N/A'),
            "region_code": resultados.get('region_code', 'N/A'),
            "latitude": resultados.get('latitude', 'N/A'),
            "longitude": resultados.get('longitude', 'N/A'),
            "os": resultados.get('os', 'N/A'),
            "asn": resultados.get('asn', 'N/A'),
            "puertos_abiertos": resultados.get('ports', []),
            "servicios": [],
            "certificados_ssl": [],
            "vulnerabilidades": [],
            "tecnologias_web": []
        }

        # Procesar servicios y certificados SSL
        for item in resultados.get('data', []):
            if not isinstance(item, dict):
                continue

            # Procesar cada servicio
            servicio = {
                'port': item.get('port'),
                'transport': item.get('transport'),
                'product': item.get('product', 'N/A'),
                'version': item.get('version', 'N/A'),
                'banner': item.get('data', 'N/A'),
                'server': item.get('http', {}).get('server', 'N/A'),
            }
            datos_ip["servicios"].append(servicio)

            # Procesar certificados SSL
            ssl_info = item.get('ssl')
            if isinstance(ssl_info, dict):
                cert = ssl_info.get('cert', {})
                cert_data = {
                    'algoritmos_cifrado': ssl_info.get('versions', []),
                    'autoridad_certificadora': cert.get('issuer', {}).get('CN', 'N/A'),
                    'fecha_emision': cert.get('validity', {}).get('start', 'N/A'),
                    'fecha_vencimiento': cert.get('validity', {}).get('end', 'N/A')
                }

                # Añadir certificado solo si no está en la lista
                if cert_data not in datos_ip['certificados_ssl']:
                    datos_ip['certificados_ssl'].append(cert_data)


            # Procesar vulnerabilidades
            vulns = item.get('vulns', {})
            for cve_id, cve_details in vulns.items():
                datos_ip['vulnerabilidades'].append({
                    'cve': cve_id,
                    'cvss': cve_details.get('cvss', 'N/A'),
                    'descripcion': cve_details.get('summary', 'Descripción no disponible'),
                    'referencias': cve_details.get('references', [])
                })

        # Procesar tecnologías web y servidores
        for item in resultados.get('data', []):
            # Verificar y capturar el servidor HTTP
            if 'http' in item:
                server = item['http'].get('server')
                if server and server not in datos_ip['tecnologias_web']:
                    datos_ip['tecnologias_web'].append(server)

                # Capturar componentes de tecnologías web desde el campo 'components'
                components = item['http'].get('components', {})
                for component, details in components.items():
                    categorias = details.get('categories', [])
                    categoria_str = ', '.join(categorias)
                    tech_detail = f"{component} ({categoria_str})" if categoria_str else component
                    if tech_detail not in datos_ip['tecnologias_web']:
                        datos_ip['tecnologias_web'].append(tech_detail)

            # Capturar productos y versiones de 'product' y 'version' si existen
            product = item.get('product')
            version = item.get('version')
            if product:
                tech = f"{product} {version}" if version else product
                if tech not in datos_ip['tecnologias_web']:
                    datos_ip['tecnologias_web'].append(tech)

            # Excluir entradas de 'cpe' y 'cpe23' de la lista de tecnologías
            # Captura otras tecnologías sin las que comienzan con 'cpe'
            non_cpe_entries = [entry for entry in item.get('cpe', []) + item.get('cpe23', []) if
                               not entry.startswith('cpe')]
            for tech in non_cpe_entries:
                if tech not in datos_ip['tecnologias_web']:
                    datos_ip['tecnologias_web'].append(tech)

        # Renderizar la plantilla HTML con los datos
        html_string = render_to_string('reports/informe_shodan_ip.html', {
            'query': ip,
            'datos_ip': datos_ip,
            'current_date': datetime.now().strftime("%d/%m/%Y"),
            'company_name': "Tesa46ti Servicios Informáticos",
            'logo_url': request.build_absolute_uri(static('images/logo.png')),
        })

        # Configurar opciones de pdfkit
        options = {
            'enable-local-file-access': True,
            'page-size': 'A4',
            'encoding': "UTF-8",
        }

        # Definir la ruta y el nombre del archivo PDF
        pdf_dir = os.path.join(settings.MEDIA_ROOT, 'pdfs')
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        pdf_filename = f"informe_ip_{ip}_{timestamp}.pdf"
        pdf_path = os.path.join(pdf_dir, pdf_filename)

        # Crear el directorio 'pdfs' si no existe
        if not os.path.exists(pdf_dir):
            os.makedirs(pdf_dir)

        # Generar y guardar el PDF en el sistema de archivos del servidor
        pdfkit.from_string(html_string, pdf_path, options=options,
                           css=os.path.join(settings.BASE_DIR, 'core/static/css/informe_ip.css'))

        # Generar la URL pública para el PDF (usando MEDIA_URL para acceso desde la web)
        pdf_url = f"{settings.MEDIA_URL}pdfs/{pdf_filename}"

        # Redirigir al `index.html` pasando el enlace al PDF
        return render(request, 'main/index.html', {
            'ip': ip,
            'pdf_url': pdf_url,
            'service_result': "Informe IP creado correctamente",
            'service_name': ""
        })

    except shodan.APIError as e:
        return render(request, 'reports/informe_shodan_ip.html', {
            'error': f"Error al obtener datos de Shodan: {str(e)}",
            'query': ip
        })
    except TypeError as te:
        return render(request, 'reports/informe_shodan_ip.html', {
            'error': f"Error de tipo: {str(te)}",
            'query': ip
        })
    except Exception as e:
        return render(request, 'reports/informe_shodan_ip.html', {
            'error': f"Error inesperado: {str(e)}",
            'query': ip
        })


def generar_pdf_whatweb(request):
    dominio = request.POST.get('dominio')

    result = subprocess.run(
        ["whatweb", "-v", dominio],
        capture_output=True,
        text=True,
        check=True
    )
    whatweb_output = result.stdout

    # Limpiar códigos ANSI
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', whatweb_output)

    # Dividir la salida por cada reporte de dominio
    report_sections = re.split(r'WhatWeb report for ', cleaned_output)
    reports = []

    for section in report_sections[1:]:
        lines = section.splitlines()
        report_info = {
            "url": lines[0].strip(),
            "status": re.search(r'Status\s+:\s+(.*)', section),
            "title": re.search(r'Title\s+:\s+(.*)', section),
            "ip": re.search(r'IP\s+:\s+(.*)', section),
            "country": re.search(r'Country\s+:\s+(.*)', section),
            "summary": re.search(r'Summary\s+:\s+(.*)', section),
            "detected_plugins": re.findall(r'\[ (.*?) \](.*?)(?=\n\[|\Z)', section, re.DOTALL),
            "http_headers": re.search(r'HTTP Headers:(.*?)(\n\n|\Z)', section, re.DOTALL)
        }

        # Formatear el resumen
        summary_formatted = []
        if report_info["summary"]:
            summary_items = report_info["summary"].group(1).strip().split(", ")
            for item in summary_items:
                formatted_item = re.sub(r'\[(.*?)\]', r': \1', item)
                summary_formatted.append(formatted_item)

        # Organizar los datos del reporte
        reports.append({
            "url": report_info["url"],
            "status": report_info["status"].group(1) if report_info["status"] else "No disponible",
            "title": report_info["title"].group(1) if report_info["title"] else "No disponible",
            "ip": report_info["ip"].group(1) if report_info["ip"] else "No disponible",
            "country": report_info["country"].group(1) if report_info["country"] else "No disponible",
            "summary": summary_formatted,
            "detected_plugins": [
                {"name": plugin[0], "details": plugin[1].strip()} for plugin in report_info["detected_plugins"]
            ],
            "http_headers": report_info["http_headers"].group(1).strip() if report_info[
                "http_headers"] else "No disponible"
        })

    # Renderizar la plantilla HTML con el contexto de datos
    html_string = render_to_string('reports/informe_whatweb_dominio.html', {
        'dominio': dominio,
        'reports': reports,
        'current_date': datetime.now().strftime("%d/%m/%Y"),
        'company_name': "Tesa46ti Servicios Informáticos",
        'logo_url': request.build_absolute_uri(static('images/logo.png'))
    })

    # Configurar pdfkit
    options = {
        'enable-local-file-access': True,
        'page-size': 'A4',
        'encoding': "UTF-8",
    }

    # Definir la ruta y el nombre del archivo PDF
    pdf_dir = os.path.join(settings.MEDIA_ROOT, 'pdfs')
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    pdf_filename = f"informe_web_{dominio}_{timestamp}.pdf"
    pdf_path = os.path.join(pdf_dir, pdf_filename)

    # Crear el directorio 'pdfs' si no existe
    if not os.path.exists(pdf_dir):
        os.makedirs(pdf_dir)

    # Generar y guardar el PDF en el sistema de archivos del servidor
    pdfkit.from_string(html_string, pdf_path, options=options,
                       css=os.path.join(settings.BASE_DIR, 'core/static/css/informe_web.css'))

    # Generar la URL pública para el PDF (usando MEDIA_URL para acceso desde la web)
    pdf_url = f"{settings.MEDIA_URL}pdfs/{pdf_filename}"

    # Redirigir al `index.html` pasando el enlace al PDF
    return render(request, 'main/index.html', {
        'dominio': dominio,
        'pdf_url': pdf_url,
        'service_result': "Informe Web creado correctamente",
        'service_name': ""
    })


def generar_pdf_wpscan(request):
    protocol = request.POST.get('protocol')
    dominio = request.POST.get('dominio')
    url = f"{protocol}{dominio}"

    try:

        result = subprocess.run(
            ["wpscan", "--url", url, "--format", "json"],
            capture_output=True,
            text=True,
        )

        wpscan_output = result.stdout
        wpscan_data = json.loads(wpscan_output)
        
        # Verifica si el escaneo fue abortado o si no se detectó WordPress
        if "scan_aborted" in wpscan_data or not wpscan_data.get("version"):
            error_message = "No se encontró un sitio de WordPress en el dominio especificado."
            messages.error(request, error_message)
            return render(request, 'main/index.html', {
                'dominio': dominio,
                'service_result': error_message,
            })

        # Extraer información de plugins con alerta de versión desactualizada
        plugins = []
        for plugin_name, plugin_info in wpscan_data.get('plugins', {}).items():
            plugin_data = {
                'name': plugin_name,
                'location': plugin_info.get('location', 'No disponible'),
                'last_updated': plugin_info.get('last_updated', 'No disponible'),
                'version': plugin_info.get('version', {}).get('number', 'No disponible') if plugin_info.get(
                    'version') else 'No disponible',
                'confidence': plugin_info.get('confidence', 0),
                'latest_version': plugin_info.get('latest_version', 'No disponible'),
                'outdated': plugin_info.get('outdated', False),
            }
            # Incluir alerta si el plugin está desactualizado
            if plugin_data['outdated']:
                plugin_data[
                    'alert'] = f"El plugin '{plugin_name}' está desactualizado. Última versión: {plugin_data['latest_version']}."
            plugins.append(plugin_data)

        # Extraer y organizar los datos relevantes
        reports = {
            'banner': wpscan_data.get('banner', {}),
            'target_url': wpscan_data.get('target_url', 'No disponible'),
            'target_ip': wpscan_data.get('target_ip', 'No disponible'),
            'version': wpscan_data.get('version', {}),
            'main_theme': wpscan_data.get('main_theme', {}),
            'plugins': plugins if plugins else [],
            'interesting_findings': wpscan_data.get('interesting_findings', []),
            'vulnerabilities': wpscan_data.get('vulnerabilities', []),
        }

        # Renderizar la plantilla HTML con el contexto de datos
        html_string = render_to_string('reports/informe_wpscan_dominio.html', {
            'url': url,
            'reports': reports,
            'current_date': datetime.now().strftime("%d/%m/%Y"),
            'company_name': "Tesa46ti Servicios Informáticos",
            'logo_url': request.build_absolute_uri(static('images/logo.png'))
        })

        # Configurar pdfkit
        options = {
            'enable-local-file-access': True,
            'page-size': 'A4',
            'encoding': "UTF-8",
        }

        # Definir la ruta y el nombre del archivo PDF
        pdf_dir = os.path.join(settings.MEDIA_ROOT, 'pdfs')
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        pdf_filename = f"informe_wpscan_{dominio}_{timestamp}.pdf"
        pdf_path = os.path.join(pdf_dir, pdf_filename)

        # Generar y guardar el PDF en el sistema de archivos del servidor
        pdfkit.from_string(html_string, pdf_path, options=options,
                           css=os.path.join(settings.BASE_DIR, 'core/static/css/informe_wordpress.css'))

        # Generar la URL pública para el PDF (usando MEDIA_URL para acceso desde la web)
        pdf_url = f"{settings.MEDIA_URL}pdfs/{pdf_filename}"

        # Redirigir al `index.html` pasando el enlace al PDF
        return render(request, 'main/index.html', {
            'dominio': dominio,
            'pdf_url': pdf_url,
            'service_result': "Informe de WordPress creado correctamente",
            'service_name': ""
        })

    except subprocess.CalledProcessError as e:
      error_message = e.stderr or "No se encuentra WordPress o no se pudo analizar."
      messages.error(request, error_message)
      return render(request, 'main/index.html', {
        'dominio': dominio,
      })





