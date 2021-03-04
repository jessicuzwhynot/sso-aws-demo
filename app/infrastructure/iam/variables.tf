variable "access_key" {
  description = "Your AWS Access Key"
  type = string
}

variable "secret_key" {
  description = "Your AWS Secret Key"
  type = string
}

variable "aws_region" {
  default = "us-east-1"
  type = string
}