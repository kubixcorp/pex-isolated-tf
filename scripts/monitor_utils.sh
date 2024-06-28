#!/bin/bash

# Actualizar los paquetes del sistema
sudo dnf update -y

# Instalar amazon-ssm-agent y telnet
sudo dnf install -y amazon-ssm-agent telnet policycoreutils-python-utils

# Habilitar y arrancar el servicio amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

sudo dnf install -y nginx

sudo semanage port -a -t http_port_t -p tcp 88

sudo systemctl stop nginx

sudo setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx

sudo semanage port -a -t http_port_t -p tcp 88

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

sudo systemctl start nginx
sudo systemctl enable nginx

echo "Script completado"
