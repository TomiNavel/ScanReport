# main/urls.py
from django.urls import path
from . import views

app_name = 'main'

urlpatterns = [
    path('', views.index, name='index'),
    path('url/', views.cargar_dominio, name='url'),
    path('ip/', views.cargar_ip, name='ip'),
]
