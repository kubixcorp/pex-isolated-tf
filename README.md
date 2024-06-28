Terraform AWS Multi-Region Network Infrastructure

Descripción

Este proyecto de Terraform crea y gestiona una infraestructura de red en AWS que abarca dos regiones: Virginia (us-east-1) y Oregon (us-west-2). La infraestructura incluye la creación de VPCs, subnets públicas y privadas, Transit Gateways, y la configuración de adjuntos y peering entre los Transit Gateways.


/Infra/
├── README.md
├── main.tf
├── outputs.tf
├── variables.tf
├── firewall/
│   ├── firewall.tf
├── modules/
│   ├── vpn/
│   │   ├── main.tf
│   │   └── variables.tf
│   ├── vpc/
│   │   ├── main.tf
│   │   └── variables.tf
│   ├── routing/
│   │   ├── main.tf
│   │   └── variables.tf
│   └── transit_gateway/
│       ├── main.tf
│       └── variables.tf

Prerrequisitos

	•	Terraform v1.0.0 o superior
	•	Credenciales de AWS configuradas

Recursos Creados

	•	VPCs:
	•	VPC-Virginia en us-east-1
	•	VPC-Oregon en us-west-2
	•	Subnets:
	•	Subnets Públicas y Privadas en ambas regiones
	•	Transit Gateways:
	•	TGW-Virginia
	•	TGW-Oregon
	•	Adjuntos de VPC:
	•	Conexión de las subnets a sus respectivos Transit Gateways
	•	Peering entre Transit Gateways:
	•	Conexión entre TGW-Virginia y TGW-Oregon    


DEBUG
terraform apply -auto-approve -parallelism=5 

export TF_LOG=INFO

export TF_LOG=DEBUG
terraform apply > terraform-debug.log
