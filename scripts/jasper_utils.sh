#!/bin/bash

# Actualizar los paquetes del sistema
sudo yum update -y

# Instalar amazon-ssm-agent y telnet
sudo yum install -y amazon-ssm-agent telnet httpd

# Habilitar y arrancar el servicio amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

systemctl start httpd
systemctl enable httpd

echo "<html><body><h1>Hello, World JASPER from ${region}!</h1><p>Current time: $(date)</p></body></html>" > /var/www/html/index.html

chown apache:apache /var/www/html/index.html

# Instalar Docker
sudo amazon-linux-extras install docker -y

# Iniciar Docker
sudo service docker start

# Habilitar Docker para que se inicie al arrancar el sistema
sudo systemctl enable docker

# Agregar el usuario ec2-user al grupo Docker
sudo usermod -aG docker ec2-user

echo "Docker se ha instalado y configurado correctamente."
echo "Por favor, cierra la sesión y vuelve a iniciarla para aplicar los cambios de grupo."

echo "Script completado"
