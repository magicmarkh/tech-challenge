module "secrets_hub_role" {
  source = "./modules/secrets_hub_role"
  CyberArkSecretsHubRoleARN = var.CyberArkSecretsHubRoleARN
  SecretsManagerRegion = var.region
}

module "users_and_roles" {
  source = "./modules/user_and_roles"
  region = var.region
}

module "sca_target_role" {
  source = "./modules/sca_target_role"
}

module "vpc" {
  source = "./modules/vpc"
  region = var.region
}