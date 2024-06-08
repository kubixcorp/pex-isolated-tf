# Instancias de Firewall en Virginia
resource "aws_instance" "cisco_firewall_virginia_a" {
  provider = aws.virginia
  ami           = "ami-12345678" # Reemplaza con el ID de la imagen de Cisco ASAv
  instance_type = "c5.large"
  subnet_id     = aws_subnet.virginia_public_a.id

  tags = {
    Name = "cisco-firewall-virginia-a"
  }
}

resource "aws_instance" "cisco_firewall_virginia_b" {
  provider = aws.virginia
  ami           = "ami-12345678" # Reemplaza con el ID de la imagen de Cisco ASAv
  instance_type = "c5.large"
  subnet_id     = aws_subnet.virginia_public_b.id

  tags = {
    Name = "cisco-firewall-virginia-b"
  }
}

# Instancias de Firewall en Oregon
resource "aws_instance" "cisco_firewall_oregon_a" {
  provider = aws.oregon
  ami           = "ami-12345678" # Reemplaza con el ID de la imagen de Cisco ASAv
  instance_type = "c5.large"
  subnet_id     = aws_subnet.oregon_public_a.id

  tags = {
    Name = "cisco-firewall-oregon-a"
  }
}

resource "aws_instance" "cisco_firewall_oregon_b" {
  provider = aws.oregon
  ami           = "ami-12345678" # Reemplaza con el ID de la imagen de Cisco ASAv
  instance_type = "c5.large"
  subnet_id     = aws_subnet.oregon_public_b.id

  tags = {
    Name = "cisco-firewall-oregon-b"
  }
}
