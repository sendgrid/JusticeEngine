provider "aws" {
  region = "us-east-1"
}

module "Justice-Engine-Krampus-S3" {
  source = "github.com/sendgrid/krampus//terraform/modules/s3"
  default_region="us-east-1"
  krampus_bucket="krampus-state"
}

