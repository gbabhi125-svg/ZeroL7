output "alb_dns_name" {
  description = "Public DNS name of the ALB fronting ZeroL7."
  value       = aws_lb.this.dns_name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "proxy_service_name" {
  value = aws_ecs_service.proxy.name
}
