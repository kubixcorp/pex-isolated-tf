#!/bin/bash

# Actualizar los paquetes del sistema
sudo yum update -y

# Instalar amazon-ssm-agent y telnet
sudo yum install -y amazon-ssm-agent telnet

# Habilitar y arrancar el servicio amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

sudo amazon-linux-extras install -y docker nginx1

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

# Iniciar Docker
sudo service docker start

# Habilitar Docker para que se inicie al arrancar el sistema
sudo systemctl enable docker

# Agregar el usuario ec2-user al grupo Docker
sudo usermod -aG docker $(whoami)

echo "Docker se ha instalado y configurado correctamente."
echo "Por favor, cierra la sesión y vuelve a iniciarla para aplicar los cambios de grupo."

echo "Script completado"
