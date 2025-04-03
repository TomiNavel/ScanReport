# Usamos una imagen base con Python
FROM python:3.13.2

# Instalamos dependencias necesarias
RUN apt-get update && \
    apt-get install -y \
    ruby \
    ruby-dev \
    build-essential \
    libcurl4-openssl-dev \
    libxml2 \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# Instalamos WPScan manualmente con RubyGems
RUN gem install wpscan

# Configuramos el directorio de trabajo
WORKDIR /app

# Copiamos los archivos del proyecto
COPY . /app

# Instalamos dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Exponemos el puerto en el que corre Django
EXPOSE 8000

# Comando para iniciar el servidor
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
