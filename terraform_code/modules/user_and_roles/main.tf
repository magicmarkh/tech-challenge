provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

# ============================================
# IAM User - candidate_user
# ============================================

resource "aws_iam_user" "candidate_user" {
  name = "candidate_user"
}

resource "aws_iam_user_login_profile" "console_user_login" {
  user                    = aws_iam_user.candidate_user.name
  password_length         = 24
  password_reset_required = true
}

# ============================================
# Inline Policy: RequireMFA (UNCHANGED - Works Great!)
# ============================================

resource "aws_iam_user_policy" "require_mfa_policy" {
  name = "RequireMFA"
  user = aws_iam_user.candidate_user.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowPasswordChangeAndMFASetupWithoutMFA",
        Effect = "Allow",
        Action = [
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:EnableMFADevice",
          "iam:GetUser"
        ],
        Resource = [
          "arn:aws:iam::*:user/$${aws:username}",
          "arn:aws:iam::*:user/*/$${aws:username}"
        ]
      },
      {
        Sid    = "AllowCreateVirtualMFADevice",
        Effect = "Allow",
        Action = [
          "iam:CreateVirtualMFADevice"
        ],
        Resource = "arn:aws:iam::*:mfa/*"
      },
      {
        Sid    = "AllowMFADeviceManagement",
        Effect = "Allow",
        Action = [
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:DeleteVirtualMFADevice"
        ],
        Resource = "arn:aws:iam::*:mfa/$${aws:username}"
      },
      {
        Sid    = "DenyAllExceptPasswordAndMFASetupIfNoMFA",
        Effect = "Deny",
        NotAction = [
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
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
    ]
  })
}

# ============================================
# NEW: Consolidated Operational Policy
# Replaces: CyberArkSCAACandidatePolicy + parts of EC2/RDS/SM policies
# ============================================

resource "aws_iam_policy" "operational_policy" {
  name        = "CyberArkCandidate-Operational"
  description = "Consolidated operational permissions for CyberArk candidate testing"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Password management (allow with or without MFA for initial setup)
      {
        Sid    = "AllowPasswordAndAccountInfo",
        Effect = "Allow",
        Action = [
          "iam:ChangePassword",
          "iam:GetUser",
          "iam:GetAccountPasswordPolicy"
        ],
        Resource = "*"
      },
      
      # EC2 - Full access (limited by cost control policy)
      {
        Sid      = "AllowEC2Operations",
        Effect   = "Allow",
        Action   = "ec2:*",
        Resource = "*"
      },
      
      # RDS - Full access (limited by cost control policy)
      {
        Sid      = "AllowRDSOperations",
        Effect   = "Allow",
        Action   = "rds:*",
        Resource = "*"
      },
      
      # Secrets Manager + KMS
      {
        Sid    = "AllowSecretsManager",
        Effect = "Allow",
        Action = [
          "secretsmanager:*",
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey",
          "kms:ListAliases"
        ],
        Resource = "*"
      },
      
      # S3 Operations
      {
        Sid    = "AllowS3Operations",
        Effect = "Allow",
        Action = [
          "s3:*"
        ],
        Resource = "*"
      },
      
      # CloudFormation
      {
        Sid    = "AllowCloudFormation",
        Effect = "Allow",
        Action = [
          "cloudformation:*"
        ],
        Resource = "*"
      },
      
      # IAM for CyberArk deployments
      {
        Sid    = "AllowIAMForCyberArk",
        Effect = "Allow",
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:ListRoles",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:GetInstanceProfile",
          "iam:ListInstanceProfiles",
          "iam:ListInstanceProfilesForRole",
          "iam:PassRole",
          "iam:CreateServiceLinkedRole",
          "iam:TagRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:GetAccountAuthorizationDetails",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "access-analyzer:ValidatePolicy"
        ],
        Resource = "*"
      },
      
      # Lambda
      {
        Sid    = "AllowLambda",
        Effect = "Allow",
        Action = [
          "lambda:*"
        ],
        Resource = "*"
      },
      
      # Logging and Monitoring
      {
        Sid    = "AllowLogging",
        Effect = "Allow",
        Action = [
          "logs:*",
          "cloudtrail:LookupEvents",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudwatch:*"
        ],
        Resource = "*"
      },
      
      # EventBridge
      {
        Sid    = "AllowEventBridge",
        Effect = "Allow",
        Action = [
          "events:*"
        ],
        Resource = "*"
      },
      
      # SNS
      {
        Sid    = "AllowSNS",
        Effect = "Allow",
        Action = [
          "sns:*"
        ],
        Resource = "*"
      },
      
      # ELB and AutoScaling
      {
        Sid    = "AllowELBAndAutoScaling",
        Effect = "Allow",
        Action = [
          "elasticloadbalancing:*",
          "autoscaling:*"
        ],
        Resource = "*"
      },
      
      # STS
      {
        Sid    = "AllowSTSGetCallerIdentity",
        Effect = "Allow",
        Action = [
          "sts:GetCallerIdentity"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_operational_policy" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = aws_iam_policy.operational_policy.arn
}

# ============================================
# NEW: Cost Control Policy
# Prevents expensive mistakes and security issues
# ============================================

resource "aws_iam_policy" "cost_control_policy" {
  name        = "CyberArkCandidate-CostControl"
  description = "Cost control and security guardrails for CyberArk candidates"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Region restrictions
      {
        Sid      = "RestrictRegions",
        Effect   = "Deny",
        Action   = "*",
        Resource = "*",
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = [
              "us-east-1",
              "us-east-2"
            ]
          }
        }
      },
      
      # EC2 instance type restrictions (FIXED LOGIC!)
      {
        Sid      = "RestrictEC2InstanceTypes",
        Effect   = "Deny",
        Action   = "ec2:RunInstances",
        Resource = "arn:aws:ec2:*:*:instance/*",
        Condition = {
          StringNotLike = {
            "ec2:InstanceType" = [
              "t3.micro",
              "t3.small",
              "t3.medium",
              "t3a.micro",
              "t3a.small",
              "t3a.medium",
              "t3a.large"
            ]
          }
        }
      },
      
      # RDS instance class restrictions (IMPROVED!)
      {
        Sid      = "RestrictRDSInstanceTypes",
        Effect   = "Deny",
        Action   = "rds:CreateDBInstance",
        Resource = "arn:aws:rds:*:*:db:*",
        Condition = {
          StringNotLike = {
            "rds:DatabaseClass" = [
              "db.t3.micro",
              "db.t4g.micro",
              "db.t3.small",
              "db.t4g.small"
            ]
          }
        }
      },
      
      # RDS engine restrictions (allow MySQL and PostgreSQL)
      {
        Sid      = "RestrictRDSEngines",
        Effect   = "Deny",
        Action   = "rds:CreateDBInstance",
        Resource = "arn:aws:rds:*:*:db:*",
        Condition = {
          StringNotLike = {
            "rds:DatabaseEngine" = [
              "mysql",
              "postgres"
            ]
          }
        }
      },
      
      # Prevent account-level modifications
      {
        Sid    = "PreventAccountModification",
        Effect = "Deny",
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:UpdateAccountPasswordPolicy",
          "iam:DeleteAccountPasswordPolicy",
          "organizations:*",
          "account:*"
        ],
        Resource = "*"
      },
      
      # Prevent billing access
      {
        Sid    = "PreventBillingAccess",
        Effect = "Deny",
        Action = [
          "aws-portal:*",
          "budgets:*",
          "ce:*",
          "cur:*",
          "purchase-orders:*"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_cost_control_policy" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = aws_iam_policy.cost_control_policy.arn
}

# ============================================
# AWS Managed Policy: IAMUserChangePassword
# ============================================

resource "aws_iam_user_policy_attachment" "allow_user_password_change" {
  user       = aws_iam_user.candidate_user.name
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}

# ============================================
# Account Password Policy
# ============================================

resource "aws_iam_account_password_policy" "default" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
}
