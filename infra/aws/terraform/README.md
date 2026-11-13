# Use the AWS Terraform configuration

## Prerequisites

- Terraform 1.15 or later
- AWS credentials with permission to manage the resources in this configuration
- An existing S3 bucket for Terraform state
- AWS CLI and the Session Manager plugin to connect to the instance

Check which AWS account your credentials use before continuing:

```sh
aws sts get-caller-identity
```

## Initialize and apply

From the repository root:

```sh
cd infra/aws/terraform
terraform init \
  -backend-config="bucket=YOUR_STATE_BUCKET" \
  -backend-config="region=YOUR_BUCKET_REGION"
terraform apply
```

The S3 state bucket must already exist. You can set local values in an ignored
`terraform.tfvars` file; see `variables.tf` for the available inputs.

## Connect with Session Manager

To connect to the EC2 instance:

```sh
INSTANCE_REGION=us-west-2

aws ssm start-session \
  --target "$(aws ec2 describe-instances \
    --filters 'Name=tag:Name,Values=ubuntu_bpf_next' \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text \
    --region "$INSTANCE_REGION")" \
  --region "$INSTANCE_REGION"
```

## Clean up

To delete all the resources managed by this configuration:

```sh
terraform destroy
```
