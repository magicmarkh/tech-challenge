module "secrets_hub_role" {
  source = "./modules/secrets_hub_role"
  CyberArkSecretsHubRoleARN = var.CyberArkSecretsHubRoleARN
  SecretsManagerRegion = var.region
}

module "users_and_roles" {
  source = "./modules/user_and_roles"
  region = var.region
}