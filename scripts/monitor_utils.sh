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

echo "<html><body><h1>Hello, World MONITOR from ${region}!</h1><p>Current time: $(date)</p></body></html>" > /var/www/html/index.html

chown apache:apache /var/www/html/index.html

echo "Script completado"
