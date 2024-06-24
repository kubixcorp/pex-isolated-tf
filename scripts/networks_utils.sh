#!/bin/bash

yum update -y
sudo yum install -y amazon-ssm-agent telnet

sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

echo "Script completado"
