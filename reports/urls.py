from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('generar_pdf_whatweb/', views.generar_pdf_whatweb, name='generar_pdf_whatweb'),
    path('generar_pdf_shodan/', views.generar_pdf_shodan, name='generar_pdf_shodan'),
    path('generar_pdf_wpscan/', views.generar_pdf_wpscan, name='generar_pdf_wpscan'),
]
