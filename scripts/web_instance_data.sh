#!/bin/bash

yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd

echo "<html><body><h1>Hello, World from ${region}!</h1></body></html>" > /var/www/html/index.html

chown apache:apache /var/www/html/index.html

echo "Script de user_data completado"
