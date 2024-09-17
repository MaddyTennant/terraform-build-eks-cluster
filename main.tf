provider "aws" {
  region  = var.region
  profile = var.profile
}

locals {
  cluster_name = "cluster-one-eks-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

# Filter out local zones, which are not currently supported 
# with managed node groups
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"

  name = "main-vpc"
  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  # Purpose: These lists are usually used to create subnets within a VPC in AWS. By defining these CICR blocks, 
  # you are specifying the IP address ranges for the ips that will be created. Not static?
  # 2 lists of CIDR blocks for private and public subnets
  # Private subnets are typically used for resources that do not need to be directly accessable form the internet,
  # such as dbs, internal app servers and backend services. 
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"] # dont match public ips on launch
  # Public subnets are typically used for resources that need to be accessed from the internet, such as web servers, load balances or NAT gateways.
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"] # do match public ips on launch

  # *****
  # Having multiple subnets in a VPC is good for high availability, fault tolerance, security and efficient resource manangement. 
  # High Availability and Fault Tolerance:
    # AZ: distrubuting subnets across multiple availablity zones. If one AZ experiences an outage, resources in other AZs can continue to operate.
    # Redundancy: Multiple subnets provide redundancy, which helps with maintaining the availability off your apps and services.
  # Security: 
    # Isolation: Different subnets to isolate different resources. For example, you can place your webservers in public subnets and your dbs in 
    # private subnets. This isolation helps in implementing security controls and reducing the attack surface.
    # Network ACLs: You can apply different NACLs (Network Access Control Lists) to different subnets to control inbound and outbound traffic at the subnet level.
  # Efficient Resource Management:
    # Traffic Management: multi subnets, for example you can route internet traffic to public subnets, and keep internal traffic within private subnets.
    # Load Balancing: Load Balancers can distribute traffic across your instances in multiple subnets, improve performance and reliablility -- load balance over subnets????
  # Scalability:
    # Resource Distribution: Multiple subnest make it easier to distribute resources accross different ip address ranges, making it easier to scale you infra 
    # without IP address exhaustion.
    # Elasitcity: you can add or remove subnets as changed in you infratructure requirements.

  # This line enables the creation of a NAT (Network Address Translation) gateway in the VPC.
  # A NAT gateway allows instances in a private subnet to connect to the internet or other AWS services, but prevents the internet from initiating connections with those instances.
  enable_nat_gateway   = true
  # This line specifies that only a single NAT gateway should be created for the VPC.
  # A NAT gateway is created in one of the public subnets
  single_nat_gateway   = true
  # enables dns names instead of using ips
  enable_dns_hostnames = true  


  # "kubernetes.io/role/elb" = 1: This tag is used by Kubernetes to identify subnets that should be used for external load balancers (ELBs). 
  # When you create a Kubernetes Service of type LoadBalancer, Kubernetes will use subnets with this tag to provision the load balancer.
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  # "kubernetes.io/role/internal-elb" = 1: This tag is used by Kubernetes to identify subnets that should be used for internal load balancers. 
  # When you create a Kubernetes Service of type LoadBalancer with the annotation service.beta.kubernetes.io/aws-load-balancer-internal: "true", 
  # Kubernetes will use subnets with this tag to provision the internal load balancer.
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.8.5"

  cluster_name    = local.cluster_name
  cluster_version = 1.29

  # This enables public access to the EKS cluster endpoint. When true clusters API server endpoint is accessable over the internet.
  # This allows you to interact with the Kubernetes API from outside the VPC where the cluster is running.
  cluster_endpoint_public_access = true
  # This setting grants the IAM user or role that created the EKS cluster administrative permissions within the Kubernetes cluster. 
  # When set to true, the cluster creator is given system:masters permissions
  enable_cluster_creator_admin_permissions = true

  cluster_addons = {
    #  AWS EBS CSI driver, which allows Kubernetes to manage AWS EBS volumes
    aws-ebs-csi-driver = {
      # This role grants the necessary permissions for the addon to interact with AWS services. arn(Amazon resource name)
      service_account_role_arn = module.irsa-ebs-csi.iam_role_arn
    }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"
  }

  eks_managed_node_groups = {
    one = {
      name = "node-group-1"

      instance_types = ["t3.small"]
      # scaling_config for number of nodes 
      # min: node group will not scale below this number
      min_size = 1
      # max: node group will not scale above this number
      max_size = 3
      # desired: node group will attempt to maintain this number under normal conditions
      desired_size = 2
    }
    two = {
      name = "node-group-2"

      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 3
      desired_size = 2
    }
  }
}

# fetching data not creating a resource
data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

module "irsa-ebs-csi" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "5.39.0"

  create_role                   = true
  role_name                     = "AmazonEKSTFEBSCSIRole-${module.eks.cluster_name}"
  provider_url                  = module.eks.oidc_provider
  role_policy_arns              = [data.aws_iam_policy.ebs_csi_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
}

resource "aws_iam_group" "test_eks_group" {
  name = "test_group"
}

resource "aws_iam_policy" "eks_full_access" {
  name        = "EKSFullAccess"
  description = "Full access to EKS"
  policy      = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "eks:*",
        "Resource": "*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "attach_eks_full_access_to_group" {
  group      = aws_iam_group.test_eks_group.name
  policy_arn = aws_iam_policy.eks_full_access.arn
}