#!/bin/bash

# Actualizar los paquetes del sistema
sudo apt-get update -y

if ! snap list amazon-ssm-agent > /dev/null 2>&1; then
  echo "amazon-ssm-agent no está instalado a través de snap. Instalando ahora..."
  sudo snap install amazon-ssm-agent --classic
else
  echo "amazon-ssm-agent ya está instalado. Actualizando ahora..."
  sudo snap refresh amazon-ssm-agent
fi

sudo systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
sudo systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service

# Instalar amazon-ssm-agent, telnet y nginx
sudo apt-get install -y telnet nginx

sudo systemctl stop nginx

# Deshabilitar cualquier configuración de Nginx que escuche en el puerto 80
sudo rm -f /etc/nginx/conf.d/default.conf

sudo tee /etc/nginx/conf.d/health_check.conf > /dev/null <<EOF
server {
    listen 88;
    server_name localhost;

    location / {
        default_type application/json;
        return 200 '{"status": "ok", "region": "${region}", "current_time": "$(date)"}';
    }
}
EOF

# Habilitar y arrancar el servicio nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# Instalar Docker usando snap
if ! snap list docker > /dev/null 2>&1; then
  echo "Docker no está instalado a través de snap. Instalando ahora..."
  sudo snap install docker
else
  echo "Docker ya está instalado. Actualizando ahora..."
  sudo snap refresh docker
fi

# Agregar el usuario actual al grupo docker
sudo usermod -aG docker $(whoami)

# Imprimir mensaje para recordar cerrar sesión y volver a iniciarla
echo "Docker se ha instalado y configurado correctamente."
echo "Por favor, cierra la sesión y vuelve a iniciarla para aplicar los cambios de grupo."

echo "Script completado"
