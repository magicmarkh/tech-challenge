data "aws_caller_identity" "current" {}

# Grab the first two AZs in the region
data "aws_availability_zones" "available" {}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "tech-challenge-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "tech-challenge-igw"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat_eip" {
  tags = {
    Name = "tech-challenge-nat-eip"
  }
}

# NAT Gateway in the first AZ
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.private[data.aws_availability_zones.available.names[0]].id

  tags = {
    Name = "tech-challenge-nat-gateway"
  }

  depends_on = [aws_internet_gateway.igw]
}

# Private route table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "tech-challenge-private-rt"
  }
}

# carve two /24s out of the VPC: one per AZ
locals {
  private_subnet_specs = [
    for idx, az in slice(data.aws_availability_zones.available.names, 0, 2) : {
      az   = az
      cidr = cidrsubnet(aws_vpc.main.cidr_block, 8, idx)
    }
  ]
}

# Create one private subnet in each AZ
resource "aws_subnet" "private" {
  for_each = { for spec in local.private_subnet_specs : spec.az => spec }

  vpc_id                  = aws_vpc.main.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = false

  tags = {
    Name = "tech-challenge-private-${each.value.az}"
  }
}

# Associate *both* private subnets with the private route table
resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}
