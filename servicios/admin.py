# servicios/admin.py
from django.contrib import admin
from .models import Dominio, IP, ResultadoDominio, ResultadoIP

@admin.register(Dominio)
class DominioAdmin(admin.ModelAdmin):
    list_display = ('nombre',)
    search_fields = ('nombre',)

@admin.register(IP)
class IPAdmin(admin.ModelAdmin):
    list_display = ('direccion',)
    search_fields = ('direccion',)

@admin.register(ResultadoDominio)
class ResultadoDominioAdmin(admin.ModelAdmin):
    list_display = ('dominio', 'servicio')
    search_fields = ('servicio', 'dominio__nombre')

@admin.register(ResultadoIP)
class ResultadoIPAdmin(admin.ModelAdmin):
    list_display = ('ip', 'servicio')
    search_fields = ('servicio', 'ip__direccion')
