#!/bin/bash

yum update -y
sudo yum install -y amazon-ssm-agent telnet httpd

sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

systemctl start httpd
systemctl enable httpd

echo "<html><body><h1>Hello, World from ${region}!</h1><p>Current time: $(date)</p></body></html>" > /var/www/html/index.html

chown apache:apache /var/www/html/index.html

echo "Script de user_data completado"
