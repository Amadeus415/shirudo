variable "region" {
  type        = string
  default     = "us-west-2"
  description = "AWS region for the Shirudo target."
}

variable "availability_zone" {
  type        = string
  default     = "us-west-2c"
  description = "Availability zone used to select the target subnet."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to AWS resources through provider default tags."
}

variable "ssm_audit_bucket" {
  type        = string
  default     = ""
  description = "Existing S3 bucket for Session Manager session logs. Empty disables the audit-bucket IAM policy."
}
