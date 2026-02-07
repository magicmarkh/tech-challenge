# CyberArk Tech Challenge - AWS Candidate Environment Setup

Automated setup for temporary AWS environments used in CyberArk SE candidate technical evaluations.

## 🚀 Quick Start

### Prerequisites

- AWS account (temporary/isolated environment recommended)
- Terraform >= 1.0
- AWS credentials configured with admin access

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/magicmarkh/tech-challenge.git
cd tech-challenge

# 2. Initialize Terraform
cd terraform_code
terraform init

# 3. Review the plan
terraform plan

# 4. Apply (creates candidate_user and all policies)
terraform apply

# 5. Get the initial password
terraform output -raw candidate_initial_password
```

**Time to deploy:** ~2 minutes

---

## 📦 What This Creates

### IAM User
- **Username:** `candidate_user`
- **Initial password:** Random 24-character (must be changed on first login)
- **MFA:** Required before any operations

### IAM Policies

1. **CyberArkCandidate-Operational** (Managed)
   - Consolidated operational permissions
   - EC2, RDS, S3, Secrets Manager, CloudFormation
   - IAM role creation for CyberArk deployments
   - Lambda, EventBridge, SNS, CloudWatch, CloudTrail

2. **CyberArkCandidate-CostControl** (Managed)
   - Region restrictions (us-east-1, us-east-2)
   - Instance type limits
   - Prevents account modifications
   - Blocks billing console access

3. **RequireMFA** (Inline)
   - Enforces MFA setup before any operations
   - Allows password change and MFA setup without MFA

### Security Controls

✅ **Region locked** to us-east-1 and us-east-2  
✅ **EC2 instances** limited to t3.micro → t3a.large  
✅ **RDS instances** limited to db.t3.micro, db.t4g.micro, db.t3.small, db.t4g.small  
✅ **RDS engines** limited to MySQL and PostgreSQL  
✅ **MFA required** before any AWS operations  
✅ **Cannot** create IAM users or access keys  
✅ **Cannot** access billing console  
✅ **Cannot** modify account password policy  

---

## 📝 Candidate Instructions

### First Login

1. **Sign in to AWS Console**
   - URL: https://console.aws.amazon.com/
   - Account ID: [Provided by SE team]
   - Username: `candidate_user`
   - Password: [Provided by SE team]

2. **Change Password** (required)
   - You'll be forced to change password on first login

3. **Set Up MFA** (required)
   - Go to: IAM → Users → candidate_user → Security Credentials
   - Click "Assign MFA device"
   - Choose "Virtual MFA device"
   - Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
   - Enter two consecutive MFA codes

4. **Sign Out and Back In**
   - Sign out
   - Sign back in with new password + MFA code
   - Now you have full access to deploy CyberArk solutions

### What You Can Do

- Deploy CyberArk SCA (Secure Cloud Access)
- Deploy CyberArk SIA (Secure Infrastructure Access)
- Deploy CyberArk SecretsHub
- Create EC2 instances (t3.micro → t3a.large)
- Create RDS databases (MySQL/PostgreSQL, small instances)
- Use AWS Secrets Manager
- Create VPCs, security groups, subnets
- Deploy CloudFormation stacks
- Create IAM roles for CyberArk
- Use Lambda, EventBridge, SNS

### Allowed Regions

- **us-east-1** (N. Virginia)
- **us-east-2** (Ohio)

**Note:** Operations in other regions will be denied.

---

## 🐛 Troubleshooting

### "Access Denied" After Login

**Cause:** MFA not set up yet

**Solution:** 
1. Go to IAM → Users → candidate_user → Security Credentials
2. Click "Assign MFA device"
3. Complete MFA setup
4. Sign out and sign back in with MFA

### "Cannot Launch EC2 Instance"

**Possible causes:**
- Wrong region (must be us-east-1 or us-east-2)
- Instance type too large (must be t3.micro → t3a.large)

**Solution:**
- Check you're in us-east-1 or us-east-2
- Use instance types: t3.micro, t3.small, t3.medium, t3a.micro, t3a.small, t3a.medium, or t3a.large

### "Cannot Create RDS Instance"

**Possible causes:**
- Wrong engine (must be MySQL or PostgreSQL)
- Instance class too large (must be db.t3.micro, db.t4g.micro, db.t3.small, or db.t4g.small)

**Solution:**
- Use MySQL or PostgreSQL
- Use small instance classes only

---

## 🧹 Cleanup After Evaluation

### Destroy Infrastructure

```bash
# In the terraform_code directory
terraform destroy
```

### Manual Cleanup (if needed)

Check for any orphaned resources:

```bash
# EC2 instances
aws ec2 describe-instances --region us-east-1 \
  --query 'Reservations[*].Instances[?State.Name!=`terminated`].[InstanceId,InstanceType]' \
  --output table

# RDS databases
aws rds describe-db-instances --region us-east-1 \
  --query 'DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus]' \
  --output table

# S3 buckets
aws s3 ls

# CloudFormation stacks
aws cloudformation list-stacks --region us-east-1 \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
  --query 'StackSummaries[*].StackName' \
  --output table

# IAM roles (CyberArk-related)
aws iam list-roles \
  --query 'Roles[?starts_with(RoleName, `CyberArk`) || starts_with(RoleName, `SCA`) || starts_with(RoleName, `SIA`)].RoleName' \
  --output table
```

Delete any found resources before destroying the environment.

---

## 📊 Cost Estimates

### With These Controls

**Typical 8-hour candidate evaluation:**
- EC2 t3.medium: ~$0.33
- RDS db.t3.micro: ~$0.16
- S3, Lambda, misc: ~$0.05
- **Total: $0.50-$1.00**

### Without Controls (Potential)

- Large instances across multiple regions: $15-70
- **Savings: ~$15-65 per candidate**

---

## 🔄 What's New in v2.0

### Major Improvements

**Fixed Critical Bug:**
- EC2 instance type policy logic was inverted (only allowed large instances!)
- Now correctly restricts to small instances

**Simplified Architecture:**
- Consolidated 4 separate policies into 2 managed policies
- Easier to maintain and understand

**Enhanced Security:**
- Added region restrictions (us-east-1, us-east-2)
- Added PostgreSQL support for RDS
- Prevent IAM user creation
- Block billing console access
- Prevent account-level modifications

**Better Cost Control:**
- Fixed instance type enforcement
- Added explicit deny policies
- Clearer instance type allowlist

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

---

## 🏗️ Architecture

```
Candidate User (candidate_user)
├── Inline Policy: RequireMFA
│   └── Blocks all operations until MFA configured
│
├── Managed Policy: CyberArkCandidate-Operational
│   ├── EC2, RDS, S3, Secrets Manager
│   ├── CloudFormation, Lambda, EventBridge
│   ├── IAM (role creation for CyberArk)
│   └── Logging (CloudWatch, CloudTrail)
│
├── Managed Policy: CyberArkCandidate-CostControl
│   ├── Deny: Other regions
│   ├── Deny: Large EC2 instances
│   ├── Deny: Large RDS instances
│   ├── Deny: IAM user creation
│   └── Deny: Billing access
│
└── AWS Managed Policy: IAMUserChangePassword
```

---

## 🛠️ Customization

### Change Allowed Regions

Edit `terraform_code/modules/user_and_roles/main.tf`:

```hcl
# In the cost_control_policy, update:
"aws:RequestedRegion" = [
  "us-east-1",
  "us-east-2",
  "eu-west-1"  # Add your region
]
```

### Change Allowed EC2 Instance Types

Edit `terraform_code/modules/user_and_roles/main.tf`:

```hcl
# In the cost_control_policy, update:
"ec2:InstanceType" = [
  "t3.micro",
  "t3.small",
  "t3.medium",
  "t3.large",    # Add larger type
  "t3a.micro",
  "t3a.small",
  "t3a.medium",
  "t3a.large"
]
```

### Change Allowed RDS Engines

Edit `terraform_code/modules/user_and_roles/main.tf`:

```hcl
# In the cost_control_policy, update:
"rds:DatabaseEngine" = [
  "mysql",
  "postgres",
  "mariadb"  # Add another engine
]
```

---

## 📚 Additional Resources

- [CyberArk Documentation](https://docs.cyberark.com/)
- [CyberArk Secure Cloud Access](https://docs.cyberark.com/secure-cloud-access/)
- [CyberArk Secure Infrastructure Access](https://docs.cyberark.com/secure-infrastructure-access/)
- [CyberArk SecretsHub](https://docs.cyberark.com/secrets-hub-privilege-cloud/)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test in a real AWS environment
5. Submit a pull request

---

## 📄 License

Internal use - CyberArk SE Team

---

## 📞 Support

For issues or questions:
- **SE Team:** se-team@cyberark.com
- **GitHub Issues:** [Create an issue](https://github.com/magicmarkh/tech-challenge/issues)

---

## ⚠️ Important Notes

- **Temporary Environments Only:** This setup is designed for isolated, temporary AWS accounts used solely for candidate evaluation
- **Not for Production:** Do not use in production AWS accounts
- **Clean Up:** Always destroy resources after evaluation to avoid unnecessary costs
- **Monitor Costs:** Even with restrictions, monitor AWS costs during candidate evaluations
