# servicios/urls.py
from django.urls import path
from . import views

app_name = 'servicios'

urlpatterns = [
    path('ip/', views.ip_dominio, name='ip_dominio'),
    path('whois/', views.whois_dominio, name='whois_dominio'),
    path('ssl/', views.certificado_ssl, name='certificado_ssl'),
    path('latency/', views.tiempo_respuesta, name='tiempo_respuesta'),
    path('blacklist/', views.verificar_lista_negra, name='verificar_lista_negra'),
    path('dns-lookup/', views.dns_lookup, name='dns_lookup'),
    path('http-status/', views.http_status, name='http_status'),
    path('ping/', views.ping_ip, name='ping_ip'),
    path('geo/', views.geo_ip, name='geo_ip'),
    path('reverse-ip/', views.reverse_ip, name='reverse_ip'),
    path('blacklist-ip/', views.blacklist_ip, name='blacklist_ip'),
    path('whois-ip/', views.whois_ip, name='whois_ip'),
]
