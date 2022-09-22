---
title: "How to Manage Your AWS Infrastructure With Terraform - Part 1"
date: 2022-09-21
layout: single
tags:
  - IaC
---

*This is a republish from my Medium blog, with minor revisions. Read my original single-page article [here](https://medium.com/swlh/how-to-manage-your-aws-infrastructure-with-terraform-3581b631fd9d), published 28.07.2020.*

## Introduction

Hashicorp Terraform is an extremely useful and flexible tool for building, changing, and versioning infrastructure safely and efficiently. It builds on the concept of Infrastructure-as-Code — managing entire infrastructures using machine-readable configuration files rather than interactive commands and configuration tools.

[Terraform](https://www.hashicorp.com/products/terraform/) is one of Hashicorp's offerings dedicated for automation. An open-source command-line version of Terraform is available for everyone through [GitHub](https://github.com/hashicorp/terraform).

Terraform works well with a wide array of private cloud providers such as VMWare vSphere as well as public cloud providers such as Google Cloud Platform (GCP), Microsoft Azure, and Amazon AWS. The full list of supported providers can be found [here](https://www.terraform.io/docs/providers/index.html).

In this detailed tutorial, I will walk you through the steps to start managing an AWS infrastructure using Terraform from scratch. This is how our AWS architecture would look like:

![](https://miro.medium.com/max/4800/1*RWibtIl8hKZe5zc_eArIwQ.jpeg)

## Prerequisites

Before we can start using Terraform to manage an AWS infrastructure, we need to set up the following:

### IAM user

As an AWS best-practice, create an IAM user with *programmatic access* and the following *policies* attached to them via Identity and Access Management (IAM) in the AWS console:

- NetworkAdministrator
- AmazonEC2FullAccess
- AmazonS3FullAccess

If you have not created an IAM user before, [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html) is a useful guide you can use. At the end of the IAM user creation process, you should be presented with the following page showing the access key ID and the secret access key. Copy these values and save them somewhere (private) because we will be using them at a later step.

For this tutorial, I have created a user called `terraform-user`.

**Remember**: always keep these credentials **confidential**!

### S3 Bucket

Create an S3 Bucket which will hold our `terraform.tfstate` file. Terraform state files are explained in a later step in this guide.

If you have not created an S3 bucket before, [here](https://medium.com/swlh/how-to-manage-your-aws-infrastructure-with-terraform-3581b631fd9d#:~:text=S3%20bucket%20before%2C-,here,-is%20a%20useful) is a useful guide you can use. For this tutorial, I have created an S3 bucket called `terraform-s3-bucket-testing`:

**Remember**: Block ALL public access to the bucket and to all the objects within the bucket.

## Installation

Now, we’re ready to install Terraform!

First, open a terminal window and create a working directory for our Terraform project. Please note that in this tutorial, I am running all commands on a macOS, so you might need to adjust commands depending on your development environment.

```bash
mkdir ~/terraform-aws
cd ~/terraform-aws
```

As of writing, the latest version of Terraform command-line is `0.12.29`. Installing Terraform on the following platforms are supported:

- macOS (64-bit)
- FreeBSD (32-bit, 64-bit, and ARM)
- Linux (32-bit, 64-bit, and ARM)
- OpenBSD (32-bit and 64-bit)
- Solaris (64-bit)
- Windows (32-bit and 64-bit)

Since I am using a macOS, I need to download the corresponding Zip file:

```bash
wget https://releases.hashicorp.com/terraform/0.12.29/terraform_0.12.29_darwin_amd64.zip
```

Alternatively, you can visit the [download page](https://www.terraform.io/downloads.html) where you can find the latest executables for your respective platform.

Next, unzip the executable and show the `terraform` binary.

```bash
unzip terraform_0.12.29_darwin_amd64.zip
ls -l terraform
```

Move the binary to a location in your `$PATH`. I would suggest moving `terraform` to `/usr/local/bin`:

```bash
mv terraform /usr/local/bin
```

Verify that the `terraform` binary is available in the current `$PATH`:

```bash
which terraform
```

If `/usr/local/bin/terraform` is displayed in the output, then we’re all set! Run this last command to check the Terraform version:

```bash
santino:terraform-aws santino$ terraform - version
Terraform v0.12.29
santino:terraform-aws santino$
```

## Terraform state

Terraform keeps a mapping between the real-world resources in the provider (in our case, Amazon AWS) with our local configuration. It does this by maintaining a `terraform.tfstate` file which by default is stored in the local working directory.

This works well if you were alone in maintaining your AWS infrastructure using Terraform. However, when working with groups, everyone who needs to execute terraform must also have a copy of the `terraform.tfstate` file on their local working directory.

An approach to solve this problem would be to commit the `terraform.tfstate` file to a Git repository so that everyone can work on the same file. However, this approach insecure, given that the state file contains **a lot of valuable information** about your AWS infrastructure. In fact, the .gitignore files in Terraform’s official git repository prevents the file from being managed by Git:

```txt
terraform.tfstate
terraform.tfstate.backup
.terraform/*
```

The best approach to this problem is to make use of a remote terraform state repository. This can be achieved in a few ways, but for this tutorial, we will be using an S3 bucket to store our `terraform.tfstate` file.

### Define the provider and remote state location

Create our first `.tf` file using your favorite editor, which will contain details about of provider (AWS) and the S3 bucket which will store our remote state.

#### provider.tf

```
# Define AWS as our provider
provider "aws" {
     region        = "eu-central-1"
}
# Terraform remote state
terraform {
     backend "s3" {
         bucket    = "terraform-s3-bucket-testing"
         key       = "terraform-s3-bucket-testing/terraform.tfstate"
         region    = "eu-central-1"
     }
}
```

The next step is to define 2 environment variables which will contain the **access key ID** and the **secret access key** from an earlier section.

```bash
export AWS_ACCESS_KEY_ID="<Access key ID here>"
export AWS_SECRET_ACCESS_KEY="<secret access key here>"
```

After defining our provider, the location of our S3 bucket, and the login credentials to our AWS account, we can now initialize our Terraform project using the `terraform init` command.

Here is a sample output:

```bash
santino:terraform-aws santino$ terraform init
Initializing the backend...
Successfully configured the backend "s3"! Terraform will automatically
use this backend unless the backend configuration changes.
Initializing provider plugins...
- Checking for available provider plugins...
- Downloading plugin for provider "aws" (hashicorp/aws) 2.70.0...
The following providers do not have any version constraints in configuration,
so the latest version was installed.
To prevent automatic upgrades to new major versions that may contain breaking
changes, it is recommended to add version = "..." constraints to the
corresponding provider blocks in configuration, with the constraint strings
suggested below.
* provider.aws: version = "~> 2.70"
Terraform has been successfully initialized!
You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.
If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
santino:terraform-aws santino$
```

*Read part 2 [here](https://www.pidnull.io/2022/09/22/How-to-Manage-Your-AWS-Infrastructure-With-Terraform-Part2.html)*

---
