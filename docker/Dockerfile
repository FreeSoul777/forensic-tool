# docker/Dockerfile (упрощенный)
FROM ubuntu:22.04

# Отключаем интерактивные диалоги
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Устанавливаем необходимые пакеты
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    sudo \
    vim \
    nano \
    iproute2 \
    netcat-openbsd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Создаем структуру директорий
RUN mkdir -p /app /data /opt/forensic

# Копируем только requirements.txt для установки зависимостей
COPY requirements.txt /tmp/requirements.txt

# Устанавливаем зависимости (но не сам пакет!)
RUN pip3 install --upgrade pip && \
    pip3 install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

WORKDIR /app

# Работаем от root
CMD ["/bin/bash"]