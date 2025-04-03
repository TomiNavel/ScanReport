from django.db import models

class Dominio(models.Model):
    nombre = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.nombre


class IP(models.Model):
    direccion = models.GenericIPAddressField(unique=True)

    def __str__(self):
        return self.direccion


class ResultadoDominio(models.Model):
    dominio = models.ForeignKey(Dominio, on_delete=models.CASCADE, related_name='resultados')
    servicio = models.CharField(max_length=100)
    resultado = models.JSONField()  # Almacenar datos en formato JSON

    def __str__(self):
        return f"{self.servicio} - {self.dominio.nombre}"


class ResultadoIP(models.Model):
    ip = models.ForeignKey(IP, on_delete=models.CASCADE, related_name='resultados')
    servicio = models.CharField(max_length=100)
    resultado = models.JSONField()  # Almacenar datos en formato JSON

    def __str__(self):
        return f"{self.servicio} - {self.ip.direccion}"
