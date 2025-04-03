# servicios/servicios_ip.py
import socket
import subprocess
import geocoder
import pydnsbl
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError


def ping_ip_service(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                capture_output=True, text=True, check=True)

        # Extrae el tiempo de respuesta del resultado
        output = result.stdout
        time_line = [line for line in output.splitlines() if "time=" in line]

        if time_line:
            time_str = time_line[0].split("time=")[-1].split(" ")[0]
            return {'status': 'success', 'data': {'Ping': f"{time_str} ms"}}
        else:
            return {'status': 'error', 'message': "No se pudo obtener el tiempo de ping."}

    except subprocess.CalledProcessError:
        return {'status': 'error', 'message': "No se pudo hacer ping a la IP."}
    except Exception as e:
        return {'status': 'error', 'message': f"Error al ejecutar ping: {str(e)}"}


def geo_ip_service(ip):
    try:
        # Obtener la geolocalización usando geocoder
        g = geocoder.ip(ip)

        if g.ok:
            ciudad = g.city if g.city else "Desconocido"
            pais = g.country if g.country else "Desconocido"
            latitud, longitud = g.latlng

            return {
                'status': 'success',
                'data': {
                    "Ciudad": ciudad,
                    "País": pais,
                    "Latitud": latitud,
                    "Longitud": longitud
                }
            }
        else:
            return {
                'status': 'error',
                'message': f"No se encontró información de geolocalización para la IP {ip}."
            }
    except Exception as e:
        return {
            'status': 'error',
            'message': f"Error al obtener geolocalización: {str(e)}"
        }


def reverse_ip_service(ip):
    try:
        host_info = socket.gethostbyaddr(ip)
        domain_names = host_info[0]
        return {
            'status': 'success',
            'data': {
                'Dominio Asociado': domain_names
            }
        }
    except socket.herror:
        return {'status': 'error', 'message': f"No se encontraron dominios asociados para la IP {ip}"}
    except Exception as e:
        return {'status': 'error', 'message': f"Error al realizar Reverse IP: {str(e)}"}


def blacklist_ip_service(ip_address):
    try:
        ip_checker = pydnsbl.DNSBLIpChecker()
        resultado = ip_checker.check(ip_address)
        if resultado.blacklisted:
            # Crear una lista de servicios que han detectado la IP en lista negra
            servicios_detectados = [detector.listing_name for detector in resultado.detected_by]
            return {
                'status': 'success',
                'data': {
                    'Mensaje': f"La IP {ip_address} está en la lista negra de {len(servicios_detectados)} servicios.",
                    'Servicios': servicios_detectados
                }
            }
        else:
            return {
                'status': 'success',
                'data': {
                    'Mensaje': f"La IP {ip_address} no está en la lista negra.",
                    'Servicios': []
                }
            }
    except Exception as e:
        return {'status': 'error', 'message': f"Error al verificar lista negra: {str(e)}"}


def whois_ip_service(ip):
    try:
        # Realizar la consulta RDAP
        obj = IPWhois(ip)
        whois_info = obj.lookup_rdap(depth=1)

        # Extraer información ASN
        asn_info = whois_info.get('asn', 'N/A')
        asn_desc = whois_info.get('asn_description', 'N/A')
        asn_country = whois_info.get('asn_country_code', 'N/A')
        asn_range = whois_info.get('asn_cidr', 'N/A')
        asn_date = whois_info.get('asn_date', 'N/A')

        # Información de las redes
        nets_info = whois_info.get('network', {})
        redes = []
        if nets_info:
            address = nets_info.get('address', 'N/A')
            address = address.replace('\n', ', ') if address else 'N/A'

            red = {
                'Rango IP': nets_info.get('cidr', 'N/A'),
                'Organización': nets_info.get('name', 'N/A'),
                'País': nets_info.get('country', 'N/A'),
                'Ciudad': nets_info.get('city', 'N/A'),
                'Dirección': address,
                'Creado': nets_info.get('created', 'N/A'),
                'Actualizado': nets_info.get('updated', 'N/A')
            }
            redes.append(red)
        else:
            redes.append({'Rango IP': 'N/A', 'Organización': 'N/A', 'País': 'N/A', 'Ciudad': 'N/A', 'Dirección': 'N/A', 'Creado': 'N/A', 'Actualizado': 'N/A'})

        # Formatear los datos para el usuario
        result = {
            'status': 'success',
            'data': {
                'ASN Info': {
                    'ASN': asn_info,
                    'Descripción ASN': asn_desc,
                    'País ASN': asn_country,
                    'Rango ASN': asn_range,
                    'Fecha ASN': asn_date
                },
                'Redes': redes
            }
        }

        return result
    except IPDefinedError:
        return {'status': 'error', 'message': f"La IP {ip} es una dirección reservada o no enrutable."}
    except ASNRegistryError:
        return {'status': 'error', 'message': f"No se encontró información ASN para la IP {ip}."}
    except Exception as e:
        return {'status': 'error', 'message': f"Error al obtener WHOIS: {str(e)}"}
