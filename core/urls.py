from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(('main.urls', 'main'), namespace='main')),
    path('login/', include(('login.urls', 'login'), namespace='login')),
    path('servicios/', include('servicios.urls', namespace='servicios')),
    path('reports/', include('reports.urls')),
]

from django.conf import settings
from django.conf.urls.static import static

# Servir archivos de media solo en modo DEBUG
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)