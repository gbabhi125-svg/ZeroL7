variable "aws_region" {
  description = "AWS region to deploy ZeroL7 into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix applied to all provisioned resource names."
  type        = string
  default     = "zerol7"
}

variable "environment" {
  description = "Deployment environment name (e.g. staging, production)."
  type        = string
  default     = "staging"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC the proxy and its backends run in."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "AZs to spread the public/private subnets across."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "proxy_image" {
  description = "Container image URI for the ZeroL7 proxy (e.g. pushed to ECR by CI)."
  type        = string
}

variable "proxy_cpu" {
  description = "Fargate task CPU units for the proxy service."
  type        = number
  default     = 512
}

variable "proxy_memory" {
  description = "Fargate task memory (MiB) for the proxy service."
  type        = number
  default     = 1024
}

variable "proxy_desired_count" {
  description = "Number of proxy task replicas to run behind the load balancer."
  type        = number
  default     = 2
}

variable "listen_port" {
  description = "Port the proxy listens on inside the container (must match config.yaml's server.listen_addr)."
  type        = number
  default     = 8080
}

variable "metrics_port" {
  description = "Port the proxy exposes Prometheus metrics on."
  type        = number
  default     = 9090
}
