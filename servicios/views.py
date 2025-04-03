# servicios/views.py
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from .models import Dominio, ResultadoDominio, ResultadoIP, IP
from . import servicios_dominio
from . import servicios_ip


@login_required
def ip_dominio(request):
    dominio = request.POST.get('dominio')
    if not dominio:
        return render(request, 'main/index.html', {'error': "No se proporcionó un dominio válido"})

    resultado = servicios_dominio.ip_service(dominio)

    return render(request, 'main/index.html', {
        'dominio': dominio,
        'service_result': resultado,
        'service_name': "ip_dominio"
    })

@login_required
def whois_dominio(request):
    dominio = request.POST.get('dominio')
    if not dominio:
        return render(request, 'main/index.html', {'error': "No se proporcionó un dominio válido"})

    resultado = servicios_dominio.whois_dominio_service(dominio)
    return render(request, 'main/index.html', {
        'dominio': dominio,
        'service_result': resultado,
        'service_name': "whois_dominio"
    })


@login_required
def certificado_ssl(request):
    dominio = request.POST.get('dominio')
    if not dominio:
        return render(request, 'main/index.html', {'error': "No se proporcionó un dominio válido"})

    resultado = servicios_dominio.certificado_ssl_service(dominio)
    return render(request, 'main/index.html', {
        'dominio': dominio,
        'service_result': resultado,
        'service_name': "certificado_ssl"
    })


@login_required
def tiempo_respuesta(request):
    dominio = request.POST.get('dominio')
    if not dominio:
        return render(request, 'main/index.html', {'error': "No se proporcionó un dominio válido"})

    resultado = servicios_dominio.latency_service(dominio)
    return render(request, 'main/index.html', {
        'dominio': dominio,
        'service_result': resultado,
        'service_name': "tiempo_respuesta"
    })


@login_required
def verificar_lista_negra(request):
    dominio = request.POST.get('dominio')
    if not dominio:
        return render(request, 'main/index.html', {'error': "No se proporcionó un dominio válido"})

    resultado = servicios_dominio.verificar_lista_negra_dominio(dominio)
    return render(request, 'main/index.html', {
        'dominio': dominio,
        'service_result': resultado,
        'service_name': "verificar_lista_negra"
    })


@login_required
def dns_lookup(request):
    dominio = request.POST.get('dominio')
    if not dominio:
        return render(request, 'main/index.html', {'error': "No se proporcionó un dominio válido"})

    resultado = servicios_dominio.dns_lookup_service(dominio)
    return render(request, 'main/index.html', {
        'dominio': dominio,
        'service_result': resultado,
        'service_name': "dns_lookup"
    })


@login_required
def http_status(request):
    dominio = request.POST.get('dominio')
    if not dominio:
        return render(request, 'main/index.html', {'error': "No se proporcionó un dominio válido"})

    resultado = servicios_dominio.http_status_service(dominio)
    return render(request, 'main/index.html', {
        'dominio': dominio,
        'service_result': resultado,
        'service_name': "http_status"
    })


@login_required
def ping_ip(request):
    ip_address = request.POST.get('ip')
    if not ip_address:
        return render(request, 'main/index.html', {'error': "No se proporcionó una IP válida"})

    resultado = servicios_ip.ping_ip_service(ip_address)
    return render(request, 'main/index.html', {
        'ip': ip_address,
        'service_result': resultado,
        'service_name': "ping_ip"
    })


@login_required
def geo_ip(request):
    ip_address = request.POST.get('ip')
    if not ip_address:
        return render(request, 'main/index.html', {'error': "No se proporcionó una IP válida"})

    resultado = servicios_ip.geo_ip_service(ip_address)
    return render(request, 'main/index.html', {
        'ip': ip_address,
        'service_result': resultado,
        'service_name': "geo_ip"
    })


@login_required
def reverse_ip(request):
    ip_address = request.POST.get('ip')
    if not ip_address:
        return render(request, 'main/index.html', {'error': "No se proporcionó una IP válida"})

    resultado = servicios_ip.reverse_ip_service(ip_address)
    return render(request, 'main/index.html', {
        'ip': ip_address,
        'service_result': resultado,
        'service_name': "reverse_ip"
    })


@login_required
def blacklist_ip(request):
    ip_address = request.POST.get('ip')
    if not ip_address:
        return render(request, 'main/index.html', {'error': "No se proporcionó una IP válida"})

    resultado = servicios_ip.blacklist_ip_service(ip_address)
    return render(request, 'main/index.html', {
        'ip': ip_address,
        'service_result': resultado,
        'service_name': "blacklist_ip"
    })


@login_required
def whois_ip(request):
    ip_address = request.POST.get('ip')
    if not ip_address:
        return render(request, 'main/index.html', {'error': "No se proporcionó una IP válida"})

    resultado = servicios_ip.whois_ip_service(ip_address)
    return render(request, 'main/index.html', {
        'ip': ip_address,
        'service_result': resultado,
        'service_name': "whois_ip"
    })