---
title: "How to Manage Your AWS Infrastructure With Terraform - Part 2"
date: 2022-09-22
layout: single
tags:
  - IaC
---

*This is a republish from my Medium blog, with minor revisions. Read my original single-page article [here](https://medium.com/swlh/how-to-manage-your-aws-infrastructure-with-terraform-3581b631fd9d), published 28.07.2020.*

[Read part 1 [here](https://www.pidnull.io/2022/09/21/How-to-Manage-Your-AWS-Infrastructure-With-Terraform-Part1.html)]

## VPC

### Managing the network

After successfully initializing our Terraform project, we can now go ahead and create resources in our AWS account.

We start with the network. We have to create a few network objects:

- VPC
- Subnets
- Internet Gateway
- Route Table

#### vpc.tf

```
## Demo VPC
resource "aws_vpc" "terraform-demo-vpc" {
     cidr_block              = "10.0.0.0/16"
     instance_tenancy        = "default"
     enable_dns_support      = "true"
     enable_dns_hostnames    = "true"
     enable_classiclink      = "false"
     tags = {
          Name = "terraform-demo-vpc"
     }
}
```

#### subnets.tf

```
## Demo subnets
# Web tier subnet
resource "aws_subnet" "terraform-demo-snet-web" {
     vpc_id                  = aws_vpc.terraform-demo-vpc.id
     cidr_block              = "10.0.0.0/21"
     map_public_ip_on_launch = "true"
     availability_zone       = "eu-central-1a"
     tags = {
          Name = "terraform-demo-snet-web"
     }
}
# Application tier subnet
resource "aws_subnet" "terraform-demo-snet-app" {
     vpc_id                  = aws_vpc.terraform-demo-vpc.id
     cidr_block              = "10.0.8.0/21"
     map_public_ip_on_launch = "false"
     availability_zone       = "eu-central-1a"
     tags = {
          Name = "terraform-demo-snet-app"
     }
}
# Database tier subnet
resource "aws_subnet" "terraform-demo-snet-db" {
     vpc_id                  = aws_vpc.terraform-demo-vpc.id
     cidr_block              = "10.0.16.0/21"
     map_public_ip_on_launch = "false"
     availability_zone       = "eu-central-1a"
     tags = {
          Name = "terraform-demo-snet-db"
     }
}
```

#### igw.tf

```
## Internet Gateway
resource "aws_internet_gateway" "terraform-demo-igw" {
     vpc_id = aws_vpc.terraform-demo-vpc.id
     tags = {
          Name  = "terraform-demo-igw"
     }
}
```

#### route-table.tf

```
## Route table
resource "aws_route_table" "terraform-demo-rtable" {
     vpc_id = aws_vpc.terraform-demo-vpc.id
     route {
          cidr_block = "0.0.0.0/0"
          gateway_id = aws_internet_gateway.terraform-demo-igw.id
     }
     tags = {
          Name = "terraform-demo-rtable"
     }
}
# Route table associations
resource "aws_route_table_association" "terraform-demo-rtassoc1" {
     subnet_id      = aws_subnet.terraform-demo-snet-web.id
     route_table_id = aws_route_table.terraform-demo-rtable.id
}
resource "aws_route_table_association" "terraform-demo-rtassoc2" {
     subnet_id      = aws_subnet.terraform-demo-snet-app.id
     route_table_id = aws_route_table.terraform-demo-rtable.id
}
resource "aws_route_table_association" "terraform-demo-rtassoc3" {
     subnet_id      = aws_subnet.terraform-demo-snet-db.id
     route_table_id = aws_route_table.terraform-demo-rtable.id
}
```

### Quick explanation!

Notice that the syntax for defining a resource is as follows:

```
 resource "<resource type>" "<resource name>"
```

We can then refer to this resource when creating other resources using the `<resource type>`.`<resource name>`.`<property>` syntax.

For example, we defined our VPC as:

```
## Demo VPC
resource "aws_vpc" "terraform-demo-vpc" {
...
```

When creating a subnet, we need to assocate it with the VPC where it should be located in. Thus, we define this association with the vpc_id parameter and the ID of the VPC:

```
resource "aws_subnet" "terraform-demo-snet-web" {
     vpc_id                  = aws_vpc.terraform-demo-vpc.id
...
```

#### Applying our changes

Use the `terraform plan` command to review the changes that Terraform would perform on our AWS infrastructure before applying them.

Sample output:

```bash
santino:terraform-aws santino$ terraform plan
Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.
------------------------------------------------------------------------
An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create
Terraform will perform the following actions:
# aws_internet_gateway.terraform-demo-igw will be created
  + resource "aws_internet_gateway" "terraform-demo-igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "terraform-demo-igw"
        }
      + vpc_id   = (known after apply)
    }
<CUT>
# aws_vpc.terraform-demo-vpc will be created
  + resource "aws_vpc" "terraform-demo-vpc" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = false
      + cidr_block                       = "10.0.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = false
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name" = "terraform-demo-vpc"
        }
    }
Plan: 9 to add, 0 to change, 0 to destroy.
------------------------------------------------------------------------
Note: You didn't specify an "-out" parameter to save this plan, so Terraform
can't guarantee that exactly these actions will be performed if
"terraform apply" is subsequently run.
santino:terraform-aws santino$
```

Since we are objects from scratch, the output of the `terraform plan` command shows that it would create 9 objects (1 VPC, 3 subnets, 1 internet gateway, 1 route table, and 3 route table associations).

To finally create the objects in AWS, run the `terraform apply` command. You will be given a final chance to review the changes and will be prompted whether or not you would like to proceed. After responding with yes, Terraform would then modify AWS to reflect your desired state.

Sample output:

```bash
santino:terraform-aws santino$ terraform apply
An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create
Terraform will perform the following actions:
# aws_internet_gateway.terraform-demo-igw will be created
  + resource "aws_internet_gateway" "terraform-demo-igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "terraform-demo-igw"
        }
      + vpc_id   = (known after apply)
    }
<CUT>
# aws_vpc.terraform-demo-vpc will be created
  + resource "aws_vpc" "terraform-demo-vpc" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = false
      + cidr_block                       = "10.0.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = false
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name" = "terraform-demo-vpc"
        }
    }
Plan: 9 to add, 0 to change, 0 to destroy.
Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.
Enter a value: yes
aws_vpc.terraform-demo-vpc: Creating...
aws_vpc.terraform-demo-vpc: Creation complete after 2s [id=vpc-03ae143c2a8e3284c]
aws_internet_gateway.terraform-demo-igw: Creating...
aws_subnet.terraform-demo-snet-app: Creating...
aws_subnet.terraform-demo-snet-db: Creating...
aws_subnet.terraform-demo-snet-web: Creating...
aws_subnet.terraform-demo-snet-app: Creation complete after 1s [id=subnet-0b6474b59034abcb0]
aws_subnet.terraform-demo-snet-db: Creation complete after 1s [id=subnet-0c5f28652ff57e71b]
aws_internet_gateway.terraform-demo-igw: Creation complete after 1s [id=igw-05519819650e3f727]
aws_route_table.terraform-demo-rtable: Creating...
aws_subnet.terraform-demo-snet-web: Creation complete after 2s [id=subnet-06bd93be3e1b13772]
aws_route_table.terraform-demo-rtable: Creation complete after 1s [id=rtb-08a56a903445b0c7c]
aws_route_table_association.terraform-demo-rtassoc3: Creating...
aws_route_table_association.terraform-demo-rtassoc2: Creating...
aws_route_table_association.terraform-demo-rtassoc1: Creating...
aws_route_table_association.terraform-demo-rtassoc1: Creation complete after 1s [id=rtbassoc-0d9d2fe02770cf4fd]
aws_route_table_association.terraform-demo-rtassoc2: Creation complete after 1s [id=rtbassoc-04e0a5bdcddd03f22]
aws_route_table_association.terraform-demo-rtassoc3: Creation complete after 1s [id=rtbassoc-0daec5cb8a9545d2a]
Apply complete! Resources: 9 added, 0 changed, 0 destroyed.
santino:terraform-aws santino$
```

You can now login to the AWS console to verify the objects created. Here is how my dashboard now looks like:

![](https://miro.medium.com/max/4800/1*nHahLD8_y1ZN1xjMZnZKUg.png)

The `terraform.tfstate` file would also be created in the S3 bucket which we have defined earlier:

![](https://miro.medium.com/max/4800/1*_cfcXS8MCuk4c9apiLCVzg.png)

## Deploying servers

Now that our VPC is ready, we can now deploy servers.

### Security groups

First, let us define 3 security groups:

- Security group that would allow inbound access to our web servers in the `terraform-demo-snet-web` subnet from the internet.
- Security group that would allow access to our application servers in the `terraform-demo-snet-app` subnet from the `terraform-demo-snet-web` subnet.
- Security group that would allow access to our database servers in the `terraform-demo-snet-db` subnet from the `terraform-demo-snet-app` subnet.

#### secgroups.tf

```
## Security groups
# Web tier security group
resource "aws_security_group" "terraform-demo-secgrp-webpub" {
        vpc_id              = aws_vpc.terraform-demo-vpc.id
        name                = "terraform-demo-secgrp-webpub"
        description         = "Allow web traffic from the internet"
        ingress {
                from_port       = 80
                to_port         = 80
                protocol        = "tcp"
                cidr_blocks     = ["0.0.0.0/0"]
                description     = "Plain HTTP"
        }
        ingress{
                from_port       = 443
                to_port         = 443
                protocol        = "tcp"
                cidr_blocks     = ["0.0.0.0/0"]
                description     = "Secure HTTP"
        }
        egress {
                from_port       = 0
                to_port         = 0
                protocol        = "-1"
                cidr_blocks     = ["0.0.0.0/0"]
        }
        tags = {
                Name = "terraform-demo-secgrp-webpub"
        }
}
# Application tier security group
resource "aws_security_group" "terraform-demo-secgrp-app" {
        vpc_id              = aws_vpc.terraform-demo-vpc.id
        name                = "terraform-demo-secgrp-app"
        description         = "Allow traffic from the web tier"
        ingress{
                from_port       = 8080
                to_port         = 8080
                protocol        = "tcp"
                cidr_blocks     = ["10.0.0.0/21"]
                description     = "Plain HTTP"
        }
        ingress{
                from_port       = 8443
                to_port         = 8443
                protocol        = "tcp"
                cidr_blocks     = ["10.0.0.0/21"]
                description     = "Secure HTTP"
        }
        egress {
                from_port       = 0
                to_port         = 0
                protocol        = "-1"
                cidr_blocks     = ["0.0.0.0/0"]
        }
        tags = {
                Name = "terraform-demo-secgrp-app"
        }
}
# Database tier security group
resource "aws_security_group" "terraform-demo-secgrp-db" {
        vpc_id              = aws_vpc.terraform-demo-vpc.id
        name                = "terraform-demo-secgrp-db"
        description         = "Allow traffic from the app tier"
        ingress{
                from_port       = 5432
                to_port         = 5432
                protocol        = "tcp"
                cidr_blocks     = ["10.0.8.0/21"]
                description     = "PostgreSQL"
        }
        ingress{
                from_port       = 3306
                to_port         = 3306
                protocol        = "tcp"
                cidr_blocks     = ["10.0.8.0/21"]
                description     = "MySQL"
        }
        ingress{
                from_port       = 27017
                to_port         = 27017
                protocol        = "tcp"
                cidr_blocks     = ["10.0.8.0/21"]
                description     = "mongodb"
        }
        egress {
                from_port       = 0
                to_port         = 0
                protocol        = "-1"
                cidr_blocks     = ["0.0.0.0/0"]
        }
        tags = {
                Name = "terraform-demo-secgrp-db"
        }
}
```

---
