# servicios/context_processors.py

def servicios_context(request):
    return {
        'servicios_dominio': {
            'Obtener IP': 'servicios:ip_dominio',
            'Whois': 'servicios:whois_dominio',
            'Certificado SSL': 'servicios:certificado_ssl',
            'Latencia': 'servicios:tiempo_respuesta',
            'Lista Negra': 'servicios:verificar_lista_negra',
            'Obtener DNS': 'servicios:dns_lookup',
            'Estado HTTP': 'servicios:http_status',
        },
        'servicios_ip': {
            'Ping': 'servicios:ping_ip',
            'Geolocalización': 'servicios:geo_ip',
            'Reverse IP': 'servicios:reverse_ip',
            'Lista Negra': 'servicios:blacklist_ip',
            'WHOIS IP': 'servicios:whois_ip',
        }
    }
