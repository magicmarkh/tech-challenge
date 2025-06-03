// provider.tf
terraform {
  required_version = ">= 1.3.0"
}

provider "aws" {
  region = var.region
}
