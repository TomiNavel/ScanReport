# servicios/servicios_dominio.py
import whois
import ssl
import socket
from datetime import datetime
import time
from spam_lists import SPAMHAUS_DBL
import dns.resolver
import requests
from OpenSSL import crypto


def ip_service(dominio):
    try:
        ip_addresses = socket.getaddrinfo(dominio, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        all_ips = set()
        for addr in ip_addresses:
            all_ips.add(addr[4][0])
        ip_list = ', '.join(all_ips)
        return {'status': 'success', 'data': {'Direcciones IP': ip_list}}
    except socket.gaierror:
        return {'status': 'error', 'message': f"No se pudo obtener la IP para el dominio {dominio}."}
    except Exception as e:
        return {'status': 'error', 'message': f"Error al obtener IP: {str(e)}"}



def whois_dominio_service(url):
    try:
        api_url = "https://whoisapi-whois-v2-v1.p.rapidapi.com/whoisserver/WhoisService"
        params = {
            "domainName": url,
            "outputFormat": "JSON",
            "apiKey": "at_Vjes7L5ExZtR4UDEJZR9RNg9MybU8"
        }

        headers = {
            "x-rapidapi-key": "b7eb5b8aa2mshaa81ffe811e77a9p1a2564jsn90b3fe523ee6",
            "x-rapidapi-host": "whoisapi-whois-v2-v1.p.rapidapi.com"
        }

        response = requests.get(api_url, headers=headers, params=params)
        data = response.json()

        if response.status_code == 200 and 'WhoisRecord' in data:
            whois_info = data['WhoisRecord']
            result = {
                'Dominio': whois_info.get('domainName', "No disponible"),
                'Servidor WHOIS': whois_info.get('registryData', {}).get('whoisServer', "No disponible"),
                'Fecha de Creación': whois_info.get('createdDate', "No disponible"),
                'Fecha de Expiración': whois_info.get('expiresDate', "No disponible"),
                'Estado': whois_info.get('status', "No disponible"),
                'Contactos Registrantes': whois_info.get('registrant', {}).get('name', "No disponible"),
                'Emails': whois_info.get('contactEmail', "No disponible"),
                'Organización': whois_info.get('registrant', {}).get('organization', "No disponible"),
                'País': whois_info.get('registrant', {}).get('country', "No disponible")
            }
            print("Resultado de WHOIS:", result)
            return {'status': 'success', 'data': result}
        else:
            print("Error en solicitud WHOIS:", data)  # Agrega un mensaje de error claro
            return {'status': 'error', 'message': f"No se pudo obtener información WHOIS para el dominio: {url}"}

    except Exception as e:
        print(f"Error en solicitud WHOIS: {str(e)}")  # Imprime cualquier excepción
        return {'status': 'error', 'message': f"Error en solicitud WHOIS: {str(e)}"}


def certificado_ssl_service(url):
    try:
        # Obtener el certificado SSL en formato PEM desde el servidor
        cert_pem = ssl.get_server_certificate((url, 443))

        if not cert_pem:
            return {'status': 'error', 'message': "No se pudo obtener un certificado SSL"}

        # Cargar el certificado utilizando OpenSSL
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        def formatear_issuer_subject(x509_name):
            # Formatear las entradas del sujeto o emisor
            try:
                return ", ".join([f"{name.decode('utf-8')}={value.decode('utf-8')}" for name, value in x509_name.get_components()])
            except Exception:
                return "No disponible"

        # Extraer y formatear la información del certificado
        try:
            valido_desde = datetime.strptime(x509.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ").strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            valido_desde = "No disponible"

        try:
            valido_hasta = datetime.strptime(x509.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ").strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            valido_hasta = "No disponible"

        # Normalizamos las claves para que no tengan espacios
        cert_info = {
            'emitido_por': formatear_issuer_subject(x509.get_issuer()),
            'valido_desde': valido_desde,
            'valido_hasta': valido_hasta,
            'sujeto': formatear_issuer_subject(x509.get_subject()),
        }

        return {'status': 'success', 'data': cert_info}
    except ssl.SSLError as e:
        return {'status': 'error', 'message': f"Error SSL: {str(e)}"}
    except Exception as e:
        return {'status': 'error', 'message': f"Error al obtener el certificado SSL: {str(e)}"}


def latency_service(url):
    try:
        start_time = time.time()
        ip_address = socket.gethostbyname(url)
        end_time = time.time()
        latency = (end_time - start_time) * 1000
        return {'status': 'success', 'data': {'Dominio': url, 'IP': ip_address, 'Latencia': f"{latency:.2f} ms"}}
    except socket.gaierror:
        return {'status': 'error', 'message': f"No se pudo resolver el dominio {url}."}
    except Exception as e:
        return {'status': 'error', 'message': f"Error al obtener la latencia: {str(e)}"}


def verificar_lista_negra_dominio(dominio):
    try:
        if dominio in SPAMHAUS_DBL:
            return {'status': 'success', 'data': {'Resultado': f"El dominio {dominio} está en la lista negra de Spamhaus."}}
        else:
            return {'status': 'success', 'data': {'Resultado': f"El dominio {dominio} no está en la lista negra."}}
    except Exception as e:
        return {'status': 'error', 'message': f"Error al verificar la lista negra para {dominio}: {str(e)}"}


def dns_lookup_service(domain):
    try:
        results = {
            "Direcciones IP (A)": [],
            "Servidores de correo (MX)": [],
            "Servidores de nombres (NS)": [],
            "Alias (CNAME)": [],
            "Registros TXT": []
        }
        try:
            a_records = dns.resolver.query(domain, 'A')
            results["Direcciones IP (A)"] = [record.to_text() for record in a_records]
        except dns.resolver.NoAnswer:
            results["Direcciones IP (A)"] = "No disponible"
        try:
            mx_records = dns.resolver.query(domain, 'MX')
            results["Servidores de correo (MX)"] = [record.to_text() for record in mx_records]
        except dns.resolver.NoAnswer:
            results["Servidores de correo (MX)"] = "No disponible"
        try:
            ns_records = dns.resolver.query(domain, 'NS')
            results["Servidores de nombres (NS)"] = [record.to_text() for record in ns_records]
        except dns.resolver.NoAnswer:
            results["Servidores de nombres (NS)"] = "No disponible"
        try:
            cname_records = dns.resolver.query(domain, 'CNAME')
            results["Alias (CNAME)"] = [record.to_text() for record in cname_records]
        except dns.resolver.NoAnswer:
            results["Alias (CNAME)"] = "No disponible"
        try:
            txt_records = dns.resolver.query(domain, 'TXT')
            results["Registros TXT"] = [record.to_text() for record in txt_records]
        except dns.resolver.NoAnswer:
            results["Registros TXT"] = "No disponible"
        return {'status': 'success', 'data': results}
    except dns.exception.DNSException as e:
        return {'status': 'error', 'message': f"Error al realizar el Estado DNS: {str(e)}"}


def http_status_service(url):
    try:
        response = requests.get(f"http://{url}")
        return {'status': 'success', 'data': {'HTTP Status': f"{response.status_code} {response.reason}"}}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': f"Error al obtener el estado HTTP: {str(e)}"}
