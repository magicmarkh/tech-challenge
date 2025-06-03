variable "region" {}

variable "private_subnet_az" {
  description = "AWS identifier for the private subnet AZ"
  default = "us-east-2b"
  type = string
}

variable "private_subnet_cidr" {
  description = "CIDR block for your private subnet"
  default = "192.168.20.0/24"
  type = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "192.168.0.0/16"
}