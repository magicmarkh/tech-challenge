variable "region" {
  description = "AWS cloud region for the deployment"
  default = "us-east-2"
  type = string
}

variable "CyberArkSecretsHubRoleARN" {
  description = "The Secrets Hub tenant role ARN which will be trusted by this role - get this from the cyberark tenant in secrets hub settings."
  type        = string
}