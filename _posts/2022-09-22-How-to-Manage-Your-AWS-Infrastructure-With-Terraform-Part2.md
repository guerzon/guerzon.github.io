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

When creating a subnet, we need to assocate it with the VPC where it should be located in. Thus, we define this association with the `vpc_id` parameter and the ID of the VPC:

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

Since we are creating objects from scratch, the output of the `terraform plan` command shows that it would create 9 objects (1 VPC, 3 subnets, 1 internet gateway, 1 route table, and 3 route table associations).

To finally create the objects in AWS, run the `terraform apply` command. You will be given a final chance to review the changes and will be prompted whether or not you would like to proceed. After responding with `yes`, Terraform would then modify AWS to reflect your desired state.

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

Again, run the same `terraform plan` command earlier and review the proposed changes, then run `terraform apply` and respond with `yes` to the prompt.

Sample output:

```bash
santino:terraform-aws santino$ terraform apply
aws_vpc.terraform-demo-vpc: Refreshing state... [id=vpc-03ae143c2a8e3284c]
<CUT>
aws_route_table_association.terraform-demo-rtassoc3: Refreshing state... [id=rtbassoc-0daec5cb8a9545d2a]
An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create
Terraform will perform the following actions:
<CUT>
# aws_security_group.terraform-demo-secgrp-webpub will be created
  + resource "aws_security_group" "terraform-demo-secgrp-webpub" {
      + arn                    = (known after apply)
      + description            = "Allow web traffic from the internet"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Plain HTTP"
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Secure HTTP"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
        ]
      + name                   = "terraform-demo-secgrp-webpub"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "terraform-demo-secgrp-webpub"
        }
      + vpc_id                 = "vpc-03ae143c2a8e3284c"
    }
Plan: 3 to add, 0 to change, 0 to destroy.
Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.
Enter a value: yes
aws_security_group.terraform-demo-secgrp-db: Creating...
aws_security_group.terraform-demo-secgrp-app: Creating...
aws_security_group.terraform-demo-secgrp-webpub: Creating...
aws_security_group.terraform-demo-secgrp-app: Creation complete after 2s [id=sg-0d920e06fa8dd370f]
aws_security_group.terraform-demo-secgrp-webpub: Creation complete after 2s [id=sg-029d4f9c83b6fed54]
aws_security_group.terraform-demo-secgrp-db: Creation complete after 2s [id=sg-049704a710b385483]
Apply complete! Resources: 3 added, 0 changed, 0 destroyed.
santino:terraform-aws santino$
```

### Server definitions

Finally, we can now deploy our servers!

First, we will query for the ID of the latest official Centos 7 AMI. Next, we will create an SSH key resource based on our own public key in `~/.ssh/id_rsa.pub`. Lastly, we will create our web server, our application server, and 2 database servers, all in their respective subnets. We would also associate each server with the corresponding security group created earlier.

#### servers.tf

```tf
## Query the  latest AMI for Centos 7
data "aws_ami" "centos7" {
    owners      = ["679593333241"]
    most_recent = true
    filter {
        name   = "name"
        values = ["CentOS Linux 7 x86_64 HVM EBS *"]
    }
    filter {
        name   = "architecture"
        values = ["x86_64"]
    }
    filter {
        name   = "root-device-type"
        values = ["ebs"]
    }
}
## SSH Key pair
resource "aws_key_pair" "terraform-demo-sshkey-santino" {
    key_name   = "terraform-demo-sshkey-santino"
    public_key = file("~/.ssh/id_rsa.pub")
        tags = {
             Name = "terraform-demo-sshkey-santino"
        }
}
### Server definitions
# Web server
resource "aws_instance" "terraform-demo-web" {
  ami                    = data.aws_ami.centos7.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.terraform-demo-sshkey-santino.key_name
  subnet_id              = aws_subnet.terraform-demo-snet-web.id
  vpc_security_group_ids = [aws_security_group.terraform-demo-secgrp-webpub.id]
        tags = {
             Name = "terraform-demo-web"
        }
}
# Application server
resource "aws_instance" "terraform-demo-app" {
  ami                    = data.aws_ami.centos7.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.terraform-demo-sshkey-santino.key_name
  subnet_id              = aws_subnet.terraform-demo-snet-app.id
  vpc_security_group_ids = [aws_security_group.terraform-demo-secgrp-app.id]
        tags = {
             Name = "terraform-demo-app"
        }
}
# Database server - Postgresql
resource "aws_instance" "terraform-demo-postgres" {
  ami                    = data.aws_ami.centos7.id
  instance_type          = "t3a.medium"
  key_name               = aws_key_pair.terraform-demo-sshkey-santino.key_name
  subnet_id              = aws_subnet.terraform-demo-snet-db.id
  vpc_security_group_ids = [aws_security_group.terraform-demo-secgrp-db.id]
        tags = {
             Name = "terraform-demo-postgres"
        }
}
# Database server - MySQL
resource "aws_instance" "terraform-demo-mysql" {
  ami                    = data.aws_ami.centos7.id
  instance_type          = "t3a.medium"
  key_name               = aws_key_pair.terraform-demo-sshkey-santino.key_name
  subnet_id              = aws_subnet.terraform-demo-snet-db.id
  vpc_security_group_ids = [aws_security_group.terraform-demo-secgrp-db.id]
        tags = {
             Name = "terraform-demo-mysql"
        }
}
```

Again, run the same `terraform plan` command earlier and review the proposed changes, then `terraform apply` and respond with `yes` to the prompt.

```bash
santino:terraform-aws santino$ terraform apply
data.aws_ami.centos7: Refreshing state...
aws_vpc.terraform-demo-vpc: Refreshing state... [id=vpc-03ae143c2a8e3284c]
aws_subnet.terraform-demo-snet-app: Refreshing state... [id=subnet-0b6474b59034abcb0]
aws_internet_gateway.terraform-demo-igw: Refreshing state... [id=igw-05519819650e3f727]
aws_subnet.terraform-demo-snet-web: Refreshing state... [id=subnet-06bd93be3e1b13772]
aws_subnet.terraform-demo-snet-db: Refreshing state... [id=subnet-0c5f28652ff57e71b]
aws_security_group.terraform-demo-secgrp-db: Refreshing state... [id=sg-049704a710b385483]
aws_security_group.terraform-demo-secgrp-app: Refreshing state... [id=sg-0d920e06fa8dd370f]
aws_security_group.terraform-demo-secgrp-webpub: Refreshing state... [id=sg-029d4f9c83b6fed54]
aws_route_table.terraform-demo-rtable: Refreshing state... [id=rtb-08a56a903445b0c7c]
aws_route_table_association.terraform-demo-rtassoc3: Refreshing state... [id=rtbassoc-0daec5cb8a9545d2a]
aws_route_table_association.terraform-demo-rtassoc1: Refreshing state... [id=rtbassoc-0d9d2fe02770cf4fd]
aws_route_table_association.terraform-demo-rtassoc2: Refreshing state... [id=rtbassoc-04e0a5bdcddd03f22]
An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create
-/+ destroy and then create replacement
Terraform will perform the following actions:
# aws_instance.terraform-demo-app will be created
  + resource "aws_instance" "terraform-demo-app" {
      + ami                          = "ami-0e8286b71b81c3cc1"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "t2.micro"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = "terraform-demo-sshkey-santino"
      + network_interface_id         = (known after apply)
      + outpost_arn                  = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = (known after apply)
      + source_dest_check            = true
      + subnet_id                    = "subnet-0b6474b59034abcb0"
      + tags                         = {
          + "Name" = "terraform-demo-app"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = (known after apply)
      + vpc_security_group_ids       = (known after apply)
+ ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
+ ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }
+ metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
        }
+ network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }
+ root_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }
<CUT>
Plan: 7 to add, 0 to change, 0 to destroy.
Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.
Enter a value: yes
<CUT>
aws_instance.terraform-demo-mysql: Creation complete after 13s [id=i-029c67de608e848b5]
aws_instance.terraform-demo-web: Still creating... [20s elapsed]
aws_instance.terraform-demo-app: Still creating... [20s elapsed]
aws_instance.terraform-demo-app: Creation complete after 22s [id=i-01363d0b335a46378]
aws_instance.terraform-demo-web: Still creating... [30s elapsed]
aws_instance.terraform-demo-web: Creation complete after 32s [id=i-059f9773402b1eb34]
Apply complete! Resources: 7 added, 0 changed, 0destroyed.
santino:terraform-aws santino$
```

Login to the EC2 Dashboard and navigate to Instances to verify the servers created:

![](https://miro.medium.com/max/4800/1*Mj_zaBpnbe0OpbNxZF3JUQ.png)

Congratulations! You have just implemented your AWS infrastructure using Terraform!

---

## Summary

In this series, we have demonstrated and learned:

- What Terraform is
- Prerequisites to using Terraform
- How to install Terraform
- Remote Terraform state
- Defining our network objects
- Deploying our servers

---

## What's next?

1. To learn more about all possible parameters you can configure for an AWS resource (such as aws_instance), refer to the official Terraform documentation: https://registry.terraform.io/providers/hashicorp/aws/latest

2. All code used in this project have been published to GitHub: https://github.com/guerzon/terraform-aws-demo. Comments are very much appreciated!
