# main/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import re


@login_required
def index(request):
    return render(request, 'main/index.html')


@login_required
def cargar_dominio(request):
    if request.method == 'POST':
        dominio = request.POST.get('dominio', '').strip()
        if not dominio or not validar_dominio(dominio):
            messages.error(request, f"Formato de dominio inválido: {dominio}")
            return redirect('main:index')
        return render(request, 'main/index.html', {'dominio': dominio})
    return render(request, 'main/index.html')


def validar_dominio(dominio):
    pattern = r"^(?!:\/\/)([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z]{2,6}$"
    return re.match(pattern, dominio) is not None


@login_required
def cargar_ip(request):
    ip = None
    if request.method == 'POST':
        ip = request.POST.get('ip', '').strip()
        if not validar_ip(ip):
            messages.error(request, f"Formato de IP inválido: {ip}")
            return redirect('main:index')
        return render(request, 'main/index.html', {'ip': ip})
    return render(request, 'main/index.html')

def validar_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) is not None

