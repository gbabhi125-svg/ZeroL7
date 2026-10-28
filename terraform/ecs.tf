resource "aws_ecs_cluster" "this" {
  name = "${local.name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "proxy" {
  name              = "/ecs/${local.name}-proxy"
  retention_in_days = 14
}

resource "aws_iam_role" "ecs_execution" {
  name = "${local.name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "proxy_task" {
  name        = "${local.name}-proxy-task-sg"
  description = "ZeroL7 proxy Fargate tasks"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "From the ALB only"
    from_port       = var.listen_port
    to_port         = var.listen_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "Metrics/health from the ALB only"
    from_port       = var.metrics_port
    to_port         = var.metrics_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-proxy-task-sg" }
}

resource "aws_ecs_task_definition" "proxy" {
  family                   = "${local.name}-proxy"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.proxy_cpu
  memory                   = var.proxy_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([
    {
      name      = "zerol7-proxy"
      image     = var.proxy_image
      essential = true
      portMappings = [
        { containerPort = var.listen_port, protocol = "tcp" },
        { containerPort = var.metrics_port, protocol = "tcp" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.proxy.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "proxy"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "proxy" {
  name            = "${local.name}-proxy"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.proxy.arn
  desired_count   = var.proxy_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.proxy_task.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name   = "zerol7-proxy"
    container_port   = var.listen_port
  }

  depends_on = [aws_lb_listener.http]
}
