provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "cyberark_candidate_role" {
  name = "CyberArkCandidateRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "cyberark_sca_candidate_policy" {
  name        = "CyberArkSCAACandidatePolicy"
  description = "Permissions required for CyberArk Cloud Visibility admin user"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "iam:GenerateCredentialReport",
          "iam:GetAccountAuthorizationDetails",
          "iam:GetCredentialReport",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListMFADevices",
          "iam:ListRolePolicies",
          "iam:ListRoles",
          "iam:ListVirtualMFADevices",
          "iam:DeleteRole",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:CreateRole",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:TagRole",
          "sns:Publish",
          "sns:ListTopics",
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "s3:BypassGovernanceRetention",
          "s3:CreateBucket",
          "s3:DeleteObjectTagging",
          "s3:DeleteObjectVersion",
          "s3:DeleteObjectVersionTagging",
          "s3:GetBucketPolicy",
          "s3:GetObject",
          "s3:GetObjectLegalHold",
          "s3:GetObjectVersion",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionTagging",
          "s3:GetObjectVersionTorrent",
          "s3:ListBuckets",
          "s3:ListBucketVersions",
          "s3:ListMultipartUploadParts",
          "s3:ObjectOwnerOverrideToBucketOwner",
          "s3:PutObject",
          "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutEncryptionConfiguration",
          "s3:PutLifecycleConfiguration",
          "s3:PutObjectLegalHold",
          "s3:PutObjectRetention",
          "s3:PutObjectVersionAcl",
          "s3:PutObjectVersionTagging",
          "s3:ReplicateDelete",
          "s3:ReplicateObject",
          "s3:ReplicateTags",
          "s3:DeleteBucket",
          "s3:DeleteBucketPolicy",
          "s3:DeleteObject",
          "s3:ListAllMyBuckets",
          "events:DescribeRule",
          "events:PutRule",
          "events:PutTargets",
          "events:RemoveTargets"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "iam:AttachRolePolicy"
        ],
        Resource : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CyberArkRoleSCA*",
        Condition : {
          "StringLike" : {
            "iam:PolicyArn" : [
              "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/CyberarkIAMAccountPermissionsPolicyForSCA*",
              "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/CyberArkPolicyAccountForSCA*"
            ]
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : "iam:PutRolePolicy",
        "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CyberArkRoleSCA*"
      },
      {
        Effect = "Allow",
        Action = [
          "iam:AttachRolePolicy"
        ],
        Resource : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CyberArkRoleForCEM*",
        Condition : {
          "StringLike" : {
            "iam:PolicyArn" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/CyberArkPolicyForCEM*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : "iam:PutRolePolicy",
        "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CyberArkRoleForCEM*"
      },
      {
        Effect = "Allow",
        Action = [
          "iam:AttachRolePolicy"
        ],
        Resource : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CyberArkDynamicPrivilegedAccess*",
        Condition : {
          "StringLike" : {
            "iam:PolicyArn" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/CyberarkJitAccountProvisioningPolicy*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : "iam:PutRolePolicy",
        "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CyberArkDynamicPrivilegedAccess*"
      },
      {
        Effect = "Allow",
        Action = [
          "cloudformation:CreateStack",
          "cloudformation:CreateStackInstances",
          "cloudformation:CreateUploadBucket",
          "cloudformation:CreateChangeSet",
          "cloudformation:DescribeChangeSet",
          "cloudformation:DescribeStackEvents",
          "cloudformation:DescribeStacks",
          "cloudformation:DescribeStackSetOperation",
          "cloudformation:GetTemplateSummary",
          "cloudformation:ListStacks",
          "cloudformation:ListStackResources",
          "cloudformation:TagResource",
          "cloudformation:UpdateStack",
          "cloudformation:DeleteStack",
          "cloudformation:DeleteStackInstances",
          "cloudformation:DeleteStackSet",
          "cloudformation:DescribeStackSet"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "sts:GetCallerIdentity"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cyberark_sca_policy_attachment" {
  role       = aws_iam_role.cyberark_candidate_role.name
  policy_arn = aws_iam_policy.cyberark_sca_candidate_policy.arn
}
