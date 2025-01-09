variable "api_users" {
  description = "Map of API users with their passwords"
  type = map(object({
    username = string
    password = string
    email    = string
    role     = string # "admin" or "user"
  }))
}

variable "environment" {
  description = "Environment (dev/prod)"
  type        = string
  default     = "dev"
}

variable "hcp_client_id" {
  description = "HCP client ID"
  type        = string
  default     = ""
}

variable "hcp_client_secret" {
  description = "HCP client secret"
  type        = string
  default     = ""
}

variable "hvn_cidr_block" {
  description = "CIDR block for HCP HVN"
  type        = string
  default     = "172.25.16.0/20"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
  default     = "992382806444"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "vault_namespace" {
  description = "Namespace of Vault"
  type        = string
  default     = "admin"
}

variable "vault_token" {
  description = "Vault token"
  type        = string
  sensitive   = true
}

variable "aws_profile" {
  description = "Profile Of User"
  type        = string
  default   = ""
}
