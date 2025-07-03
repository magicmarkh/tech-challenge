provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

resource "aws_iam_user" "candidate_user" {
  name = "candidate_user"

}

resource "aws_iam_user_login_profile" "console_user_login" {
  user                    = aws_iam_user.candidate_user.name
  password_length         = 24
  password_reset_required = true
}

resource "aws_iam_user_policy" "require_mfa_policy" {
  name = "RequireMFA"
  user = aws_iam_user.candidate_user.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [

      # 1) Pre-MFA: allow exactly these calls so the user can reset their password and
      #    register an MFA device on first login.
      {
        Sid    = "AllowPasswordChangeAndMFASetupWithoutMFA",
        Effect = "Allow",
        Action = [
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:GetUser"
        ],
        Resource = [
          "arn:aws:iam::*:user/$${aws:username}",
          "arn:aws:iam::*:user/*/$${aws:username}",
          "arn:aws:iam::*:mfa/$${aws:username}"
        ]
      },

      # 2) Pre-MFA: deny absolutely everything else not in the list above
      {
        Sid    = "DenyAllExceptPasswordAndMFASetupIfNoMFA",
        Effect = "Deny",
        NotAction = [
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:GetUser"
        ],
        Resource = "*",
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }

      # <-- no "Allow * with MFA" here.  Once MFA = true, this inline policy has
      #     no denies, so your other attached policies will control access.
    ]
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
          "access-analyzer:ValidatePolicy",
          "iam:CreateServiceLinkedRole",
          "iam:GenerateCredentialReport",
          "iam:GetAccountAuthorizationDetails",
          "iam:GetCredentialReport",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListMFADevices",
          "iam:ListInstanceProfiles",
          "iam:ListInstanceProfilesForRole",
          "iam:ListPolicies",
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
          "iam:CreateInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:PassRole",
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
          "s3:ListAllMyBuckets",
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
        "Action" : "iam:AttachRolePolicy",
        "Resource" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*",
        "Condition" : {
          "StringLike" : {
            "iam:PolicyArn" : [
              "arn:aws:iam::aws:policy/*",
              "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*"
            ]
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

resource "aws_iam_user_policy_attachment" "attach_cyberark_sca_candidate_policy" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = aws_iam_policy.cyberark_sca_candidate_policy.arn
}

resource "aws_iam_policy" "ec2_policy" {
  name        = "CyberArkCandidateEC2Policy"
  description = "Candidate EC2 policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [

      #allow everything in EC2
      {
        Sid      = "AllowAllEC2Actions",
        Effect   = "Allow",
        Action   = "ec2:*",
        Resource = "*"
      },
      #allow cloudwatch alarms
      {
        Sid      = "AllowCloudwatchAlarm",
        Effect   = "Allow",
        Action   = "cloudwatch:DescribeAlarms",
        Resource = "*"
      },
      #require samll image sizes
      {
        Sid    = "DenyRunInstancesUnlessSmall",
        Effect = "Deny",
        Action = "ec2:RunInstances",
        Resource = [
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:image/*"
        ],
        Condition = {
          StringNotEquals = {
            "ec2:InstanceType" = [
              "t3a.medium",
              "t3a.large"
            ]
          }
        }
      }

    ]
  })
}


resource "aws_iam_user_policy_attachment" "attach_ec2_policy" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = aws_iam_policy.ec2_policy.arn
}


resource "aws_iam_policy" "rds_policy" {
  name        = "CyberArkCandidateRDSPolicy"
  description = "Allow full RDS admin, but CreateDBInstance only for MySQL + small instance"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [

      # 1) Allow everything RDS
      {
        Sid      = "AllowAllRDSActions",
        Effect   = "Allow",
        Action   = "rds:*",
        Resource = "*"
      },

      # 2) Deny CreateDBInstance unless engine = mysql
      {
        Sid      = "DenyCreateNonMySQLEngine",
        Effect   = "Deny",
        Action   = "rds:CreateDBInstance",
        Resource = "*",
        Condition = {
          StringNotEquals = {
            "rds:DatabaseEngine" = "mysql"
          }
        }
      },

      # 3) Deny CreateDBInstance unless class = db.t4g.micro
      {
        Sid      = "DenyCreateNonSmallClass",
        Effect   = "Deny",
        Action   = "rds:CreateDBInstance",
        Resource = "*",
        Condition = {
          StringNotEquals = {
            "rds:DatabaseClass" = "db.t4g.micro"
          }
        }
      },

      # 4) Allow RDS to create its service‐linked role
      {
        Sid      = "AllowCreateRDSServiceLinkedRole",
        Effect   = "Allow",
        Action   = "iam:CreateServiceLinkedRole",
        Resource = "*",
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = "rds.amazonaws.com"
          }
        }
      }
    ]
  })
}


resource "aws_iam_user_policy_attachment" "attach_cyberark_rds_candidate_policy" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = aws_iam_policy.rds_policy.arn
}

resource "aws_iam_policy" "aws_sm_policy" {
  name        = "CyberArkCandidateAWSSMPolicy"
  description = "Least-privilege policy for full Secrets Manager administration"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "secretsmanager:*",
        Resource = "*"
      },
      #KMS support
      {
        Effect = "Allow",
        Action = [
          "kms:DescribeKey",
          "kms:ListAliases"
        ],
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_user_policy_attachment" "attach_cyberark_aws_sm_candidate_policy" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = aws_iam_policy.aws_sm_policy.arn
}

resource "aws_iam_user_policy_attachment" "allow_user_password_change" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}


resource "aws_iam_account_password_policy" "default" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
}
