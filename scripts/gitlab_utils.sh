#!/bin/bash

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

sudo apt-get install -y telnet

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
