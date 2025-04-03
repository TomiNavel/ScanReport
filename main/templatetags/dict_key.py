# main/templatetags/dict_key.py
from django import template

register = template.Library()

@register.filter(name='get_value')
def get_value(d, key):
    """Devuelve el valor de un diccionario si la clave existe, de lo contrario, devuelve 'No disponible'."""
    if isinstance(d, dict):
        return d.get(key, "No disponible")
    return "No disponible"

@register.filter(name='split')
def split(value, delimiter=", "):
    """ Divide la cadena por el delimitador especificado """
    return value.split(delimiter)
