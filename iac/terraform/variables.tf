variable "project_id" { type = string }
variable "region"     { type = string }
variable "zone"       { type = string }
variable "network_name" { type = string  default = "zt-mysql-net" }
variable "subnet_cidr" { type = string  default = "10.10.0.0/24" }
variable "instance_name" { type = string default = "zt-mysql-vm" }
variable "machine_type" { type = string default = "e2-standard-4" }
variable "image" { type = string default = "ubuntu-2204-jammy-v20240710" }
variable "service_account_email" { type = string }
variable "allow_cidrs" { type = list(string) default = [] }