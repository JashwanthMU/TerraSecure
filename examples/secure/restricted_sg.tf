resource "aws_security_group" "web_server" {
  name        = "web_server"
  description = "Allow HTTPS from internal network"
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}