# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-02-06

### 🎯 Summary
Major overhaul of IAM policies with critical bug fixes, simplified architecture, and enhanced security controls.

### Added
- **Region restrictions** - All operations now limited to us-east-1 and us-east-2
- **Account protection** - Prevents IAM user creation and access key generation
- **Billing protection** - Blocks access to billing console and cost management
- **PostgreSQL support** - RDS now allows both MySQL and PostgreSQL databases
- **Expanded RDS options** - Additional instance classes (db.t3.small, db.t4g.small)
- **Comprehensive README** - Complete documentation for setup and troubleshooting
- **This CHANGELOG** - Version history documentation

### Changed
- **Simplified policy structure** - Consolidated from 4 separate policies into 2 managed policies
  - Old: `CyberArkSCAACandidatePolicy`, `CyberArkCandidateEC2Policy`, `CyberArkCandidateRDSPolicy`, `CyberArkCandidateAWSSMPolicy`
  - New: `CyberArkCandidate-Operational`, `CyberArkCandidate-CostControl`
- **Improved policy names** - More descriptive and consistent naming convention
- **Better organized code** - Clear sections with comments in Terraform

### Fixed
- **CRITICAL: EC2 instance type logic was inverted** 🚨
  - **Old behavior:** Policy only allowed t3a.medium and t3a.large (the expensive ones!)
  - **Root cause:** Used `StringNotEquals` with `Deny`, which inverted the logic
  - **New behavior:** Correctly allows t3.micro through t3a.large
  - **Impact:** Prevented candidates from launching small instances, allowed only large ones
  - **Fix:** Changed to `StringNotLike` with whitelist approach
- **Missing region restrictions** - Operations could occur in any AWS region globally
- **Overly permissive IAM** - Could attach any AWS managed policy to roles
- **No RDS engine restrictions** - Could create expensive Oracle/SQL Server databases
- **Account-level exposure** - No prevention of IAM user creation or billing access

### Security Enhancements
- Explicit deny policies prevent privilege escalation
- Region-based access control prevents resource sprawl
- Instance type enforcement prevents cost overruns
- MFA enforcement maintained from v1.0

### Migration Notes
- **Breaking changes:** Policy names have changed
- **Backward compatibility:** Terraform will handle the transition automatically
- **Action required:** Run `terraform apply` to migrate
- **No candidate impact:** Candidate workflow unchanged

### Cost Impact
- **Before:** Potential $15-70 per candidate (with bugs)
- **After:** Typical $0.50-1.00 per candidate
- **Savings:** ~$15-65 per candidate evaluation

---

## [1.0.0] - Previous Version

### Initial Release

#### Features
- Terraform-based IAM user creation
- Multiple separate IAM policies:
  - CyberArkSCAACandidatePolicy - SCA/SIA deployment permissions
  - CyberArkCandidateEC2Policy - EC2 permissions (with bug)
  - CyberArkCandidateRDSPolicy - RDS permissions (MySQL only)
  - CyberArkCandidateAWSSMPolicy - Secrets Manager permissions
- MFA enforcement via inline policy
- Password complexity requirements
- Console password with forced reset

#### Known Issues (Fixed in 2.0.0)
- EC2 instance type policy logic inverted
- No region restrictions
- No account-level protections
- No billing access prevention
- Limited RDS engine options
- Complex policy management

---

## Version Comparison

### Policy Architecture

| Aspect | v1.0 | v2.0 |
|--------|------|------|
| Number of policies | 4 managed + 1 inline | 2 managed + 1 inline |
| EC2 logic | ❌ Inverted (broken) | ✅ Fixed |
| Region control | ❌ None | ✅ us-east-1, us-east-2 |
| Account protection | ❌ None | ✅ Full |
| Billing access | ❌ Allowed | ✅ Denied |
| RDS engines | MySQL only | MySQL + PostgreSQL |
| Cost per candidate | $15-70 (with bugs) | $0.50-1.00 |

### What Stayed the Same

✅ MFA enforcement (inline policy - unchanged)  
✅ Password change policy (AWS managed - unchanged)  
✅ User creation workflow  
✅ Terraform-based deployment  
✅ VPC, SecretsHub, SCA modules  

---

## Upgrade Instructions

### From v1.0 to v2.0

1. **Backup your current state:**
   ```bash
   terraform state pull > terraform.tfstate.backup
   ```

2. **Update your code:**
   ```bash
   git pull origin main
   ```

3. **Review the changes:**
   ```bash
   terraform plan
   ```

4. **Apply the updates:**
   ```bash
   terraform apply
   ```

5. **Verify the changes:**
   ```bash
   # Check policies exist
   aws iam list-attached-user-policies --user-name candidate_user
   
   # Verify MFA requirement
   aws iam list-user-policies --user-name candidate_user
   ```

### What Happens During Upgrade

Terraform will:
- ✅ Create 2 new policies (CyberArkCandidate-Operational, CyberArkCandidate-CostControl)
- ✅ Attach new policies to existing user
- ✅ Detach old policies
- ✅ Delete old policies
- ✅ Keep MFA inline policy unchanged
- ✅ Keep user and login profile unchanged

**No downtime:** Candidate user remains functional throughout

---

## Testing Checklist for Each Release

### Pre-Release Testing
- [ ] Deploy in fresh AWS account
- [ ] Create candidate user successfully
- [ ] Verify password reset required
- [ ] Test MFA enforcement blocks operations
- [ ] Test MFA setup process works
- [ ] Verify EC2 instance type restrictions work correctly
- [ ] Verify region restrictions block other regions
- [ ] Test RDS creation with allowed engines
- [ ] Test RDS creation fails with disallowed engines
- [ ] Verify candidate can deploy CyberArk SCA
- [ ] Verify candidate can deploy CyberArk SIA
- [ ] Test Secrets Manager access
- [ ] Test CloudFormation deployments
- [ ] Verify billing console is blocked
- [ ] Test cleanup/teardown process

### Post-Release Validation
- [ ] Verify no AccessDenied errors in CloudTrail (except expected ones)
- [ ] Confirm cost controls are working
- [ ] Check for any unexpected resource creation
- [ ] Validate documentation accuracy

---

## Bug Reporting

Found a bug? Please report it with:
1. What you were trying to do
2. What you expected to happen
3. What actually happened
4. Terraform version
5. AWS region
6. Relevant CloudTrail logs (if applicable)

Open an issue on GitHub or contact the SE team.

---

## Future Enhancements (Planned)

### Under Consideration
- [ ] CloudShell one-click deployment script
- [ ] Automated orphaned resource cleanup
- [ ] Cost alerting integration
- [ ] Multi-region support (configurable)
- [ ] Additional database engine options
- [ ] Terraform Cloud integration
- [ ] Automated testing pipeline

### Feedback Welcome
Have ideas for improvements? Open an issue or submit a PR!

---

**Maintained by:** CyberArk SE Team  
**Last Updated:** February 2025
