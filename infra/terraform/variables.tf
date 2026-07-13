variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-2"
}

variable "ami_id" {
  description = "AMI ID used by both EC2 Instances"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "subnet_id" {
  description = "Subnet for both EC2 instances"
  type        = string
}

variable "key_name" {
  description = "Existing Ec2 key pair name"
  type        = string
}

variable "elevpn_server_security_group_id" {
  description = "Security group for elevpn-server"
  type        = string
}

variable "elevpn_client_security_group_id" {
  description = "Security group for elevpn-client"
  type        = string
}