resource "aws_security_group" "ssh_access" {
  name        = "ssh_access"
  description = "Allow SSH from anywhere"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}