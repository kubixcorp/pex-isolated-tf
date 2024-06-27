#!/bin/bash

# Actualizar los paquetes del sistema
sudo apt-get update -y

# Instalar amazon-ssm-agent, telnet y apache2
sudo apt-get install -y amazon-ssm-agent telnet apache2

# Habilitar y arrancar el servicio amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

# Habilitar y arrancar el servicio apache2
sudo systemctl start apache2
sudo systemctl enable apache2

# Crear una página de bienvenida
echo "<html><body><h1>Hello, World OPENVPN from ${region}!</h1><p>Current time: $(date)</p></body></html>" | sudo tee /var/www/html/index.html

# Establecer permisos para el archivo HTML
sudo chown www-data:www-data /var/www/html/index.html

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
