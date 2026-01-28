#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "============================================"
echo "  AWS Organization Baseline"
echo "============================================"
echo ""

# Check AWS credentials
echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"
    echo "Please provide AWS credentials via:"
    echo "  - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)"
    echo "  - Mounted ~/.aws directory with AWS_PROFILE set"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text)
echo -e "${GREEN}Authenticated to account: ${ACCOUNT_ID}${NC}"
echo -e "${GREEN}Caller: ${CALLER_ARN}${NC}"
echo ""

# Load configuration from config.yaml (with environment variable overrides)
echo -e "${YELLOW}Loading configuration...${NC}"

# VPC_BLOCK_MODE can be overridden via environment variable (ingress, bidirectional, disabled)
if [ -n "${VPC_BLOCK_MODE:-}" ]; then
    echo -e "${BLUE}Using VPC_BLOCK_MODE from environment: ${VPC_BLOCK_MODE}${NC}"
else
    VPC_BLOCK_MODE=$(python3 -c "import yaml; print(yaml.safe_load(open('/work/config.yaml')).get('vpc_block_public_access', {}).get('mode', 'ingress'))" 2>/dev/null || echo "ingress")
fi
export VPC_BLOCK_MODE

PRIMARY_REGION=$(python3 -c "import yaml; print(yaml.safe_load(open('/work/config.yaml'))['primary_region'])" 2>/dev/null || echo "us-east-1")
RESOURCE_PREFIX=$(python3 -c "import yaml; print(yaml.safe_load(open('/work/config.yaml'))['resource_prefix'])" 2>/dev/null)
if [ -z "${RESOURCE_PREFIX}" ]; then
    echo -e "${RED}Error: resource_prefix is required in config.yaml${NC}"
    exit 1
fi
echo -e "${GREEN}Primary region: ${PRIMARY_REGION}${NC}"
echo -e "${GREEN}Resource prefix: ${RESOURCE_PREFIX}${NC}"
echo ""

# State bucket configuration
STATE_BUCKET="${RESOURCE_PREFIX}-tfstate-${ACCOUNT_ID}"
STATE_KEY="organization/terraform.tfstate"
STATE_REGION="${PRIMARY_REGION}"

# Step 1: Create state bucket if it doesn't exist (bootstrap only)
echo -e "${YELLOW}Checking Terraform state bucket...${NC}"
if ! aws s3api head-bucket --bucket "${STATE_BUCKET}" 2>/dev/null; then
    echo -e "${YELLOW}Creating state bucket: ${STATE_BUCKET}${NC}"

    # Create KMS key for state bucket
    echo -e "${YELLOW}Creating KMS key for state bucket...${NC}"
    KMS_KEY_ID=$(aws kms create-key \
        --description "KMS key for Terraform state bucket encryption" \
        --tags TagKey=Name,TagValue=${RESOURCE_PREFIX}-tfstate-key \
               TagKey=Purpose,TagValue="S3 bucket encryption" \
               TagKey=ProtectsBucket,TagValue="${STATE_BUCKET}" \
               TagKey=ManagedBy,TagValue=portfolio-aws-org-baseline \
        --region "${STATE_REGION}" \
        --query 'KeyMetadata.KeyId' \
        --output text \
        --no-cli-pager)

    # Create alias for the key
    aws kms create-alias \
        --alias-name "alias/${RESOURCE_PREFIX}-tfstate" \
        --target-key-id "${KMS_KEY_ID}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    # Enable key rotation
    aws kms enable-key-rotation \
        --key-id "${KMS_KEY_ID}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    KMS_KEY_ARN="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${KMS_KEY_ID}"

    # Create bucket (us-east-1 doesn't use LocationConstraint)
    if [ "${STATE_REGION}" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "${STATE_BUCKET}" \
            --region "${STATE_REGION}" \
            --no-cli-pager
    else
        aws s3api create-bucket \
            --bucket "${STATE_BUCKET}" \
            --region "${STATE_REGION}" \
            --create-bucket-configuration LocationConstraint="${STATE_REGION}" \
            --no-cli-pager
    fi

    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "${STATE_BUCKET}" \
        --versioning-configuration Status=Enabled \
        --no-cli-pager

    # Enable KMS encryption
    aws s3api put-bucket-encryption \
        --bucket "${STATE_BUCKET}" \
        --server-side-encryption-configuration "{
            \"Rules\": [{
                \"ApplyServerSideEncryptionByDefault\": {
                    \"SSEAlgorithm\": \"aws:kms\",
                    \"KMSMasterKeyID\": \"${KMS_KEY_ARN}\"
                },
                \"BucketKeyEnabled\": true
            }]
        }" \
        --no-cli-pager

    # Block public access
    aws s3api put-public-access-block \
        --bucket "${STATE_BUCKET}" \
        --public-access-block-configuration '{
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
        }' \
        --no-cli-pager

    # Add bucket policy for SSL enforcement
    aws s3api put-bucket-policy \
        --bucket "${STATE_BUCKET}" \
        --policy "{
            \"Version\": \"2012-10-17\",
            \"Statement\": [
                {
                    \"Sid\": \"DenyNonSSL\",
                    \"Effect\": \"Deny\",
                    \"Principal\": \"*\",
                    \"Action\": \"s3:*\",
                    \"Resource\": [
                        \"arn:aws:s3:::${STATE_BUCKET}\",
                        \"arn:aws:s3:::${STATE_BUCKET}/*\"
                    ],
                    \"Condition\": {
                        \"Bool\": {
                            \"aws:SecureTransport\": \"false\"
                        }
                    }
                }
            ]
        }" \
        --no-cli-pager

    echo -e "${GREEN}State bucket created with KMS encryption${NC}"
else
    echo -e "${GREEN}State bucket exists${NC}"

    # Check if bucket already has KMS encryption
    CURRENT_ENCRYPTION=$(aws s3api get-bucket-encryption \
        --bucket "${STATE_BUCKET}" \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
        --output text 2>/dev/null || echo "NONE")

    if [ "${CURRENT_ENCRYPTION}" != "aws:kms" ]; then
        echo -e "${YELLOW}Upgrading state bucket to KMS encryption...${NC}"

        # Check if KMS key alias exists
        if ! aws kms describe-key --key-id "alias/${RESOURCE_PREFIX}-tfstate" --region "${STATE_REGION}" 2>/dev/null; then
            # Create KMS key for state bucket
            KMS_KEY_ID=$(aws kms create-key \
                --description "KMS key for Terraform state bucket encryption" \
                --tags TagKey=Name,TagValue=${RESOURCE_PREFIX}-tfstate-key \
                       TagKey=Purpose,TagValue="S3 bucket encryption" \
                       TagKey=ProtectsBucket,TagValue="${STATE_BUCKET}" \
                       TagKey=ManagedBy,TagValue=portfolio-aws-org-baseline \
                --region "${STATE_REGION}" \
                --query 'KeyMetadata.KeyId' \
                --output text \
                --no-cli-pager)

            # Create alias for the key
            aws kms create-alias \
                --alias-name "alias/${RESOURCE_PREFIX}-tfstate" \
                --target-key-id "${KMS_KEY_ID}" \
                --region "${STATE_REGION}" \
                --no-cli-pager

            # Enable key rotation
            aws kms enable-key-rotation \
                --key-id "${KMS_KEY_ID}" \
                --region "${STATE_REGION}" \
                --no-cli-pager
        else
            KMS_KEY_ID=$(aws kms describe-key \
                --key-id "alias/${RESOURCE_PREFIX}-tfstate" \
                --region "${STATE_REGION}" \
                --query 'KeyMetadata.KeyId' \
                --output text)
        fi

        KMS_KEY_ARN="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${KMS_KEY_ID}"

        # Update bucket encryption
        aws s3api put-bucket-encryption \
            --bucket "${STATE_BUCKET}" \
            --server-side-encryption-configuration "{
                \"Rules\": [{
                    \"ApplyServerSideEncryptionByDefault\": {
                        \"SSEAlgorithm\": \"aws:kms\",
                        \"KMSMasterKeyID\": \"${KMS_KEY_ARN}\"
                    },
                    \"BucketKeyEnabled\": true
                }]
            }" \
            --no-cli-pager

        echo -e "${GREEN}State bucket upgraded to KMS encryption${NC}"
    fi
fi
echo ""

# Parse command line arguments
ACTION="${1:-apply}"
TERRAFORM_ARGS="${@:2}"

case "$ACTION" in
    discover)
        echo -e "${YELLOW}Running discovery only...${NC}"
        python3 /work/discovery/discover.py
        exit 0
        ;;
    shell)
        echo -e "${YELLOW}Opening interactive shell...${NC}"
        exec /bin/bash
        ;;
    state-cleanup)
        echo -e "${YELLOW}Running state cleanup for removed GuardDuty modules...${NC}"
        cd /work/terraform
        rm -rf .terraform .terraform.lock.hcl
        terraform init -input=false \
            -backend-config="bucket=${STATE_BUCKET}" \
            -backend-config="key=${STATE_KEY}" \
            -backend-config="region=${STATE_REGION}" \
            -backend-config="encrypt=true"
        echo ""
        echo -e "${YELLOW}Removing management and log_archive GuardDuty detectors from state...${NC}"
        for region in us_east_1 us_east_2 us_west_1 us_west_2 eu_west_1 eu_west_2 eu_west_3 \
                      eu_central_1 eu_north_1 ap_southeast_1 ap_southeast_2 ap_northeast_1 \
                      ap_northeast_2 ap_northeast_3 ap_south_1 ca_central_1 sa_east_1; do
            terraform state rm "module.guardduty_mgmt_${region}[0].aws_guardduty_detector.main" 2>/dev/null || true
            terraform state rm "module.guardduty_log_archive_${region}[0].aws_guardduty_detector.main" 2>/dev/null || true
        done
        echo -e "${GREEN}State cleanup complete${NC}"
        exit 0
        ;;
    plan)
        TF_ACTION="plan"
        ;;
    apply)
        TF_ACTION="apply -auto-approve"
        ;;
    destroy)
        TF_ACTION="destroy -auto-approve"
        ;;
    *)
        echo "Usage: $0 [discover|plan|apply|destroy|shell|state-cleanup]"
        exit 1
        ;;
esac

# Phase 1: Discovery
echo ""
echo "============================================"
echo "  Phase 1: Discovery"
echo "============================================"
echo ""
python3 /work/discovery/discover.py
echo ""

# Phase 1.5: Control Tower Region Governance (apply mode only)
if [ "$TF_ACTION" = "apply -auto-approve" ]; then
    # Check if Control Tower was detected
    CT_EXISTS=$(python3 -c "
import json
from pathlib import Path
try:
    with open('/work/terraform/discovery.json') as f:
        d = json.load(f)
        print('true' if d.get('control_tower_exists', False) else 'false')
except:
    print('false')
")

    if [ "$CT_EXISTS" = "true" ]; then
        echo ""
        echo "============================================"
        echo "  Phase 1.5: Control Tower Region Governance"
        echo "============================================"
        echo ""

        # Run Control Tower regions helper in apply mode
        export DISCOVER_MODE=apply
        export PRIMARY_REGION="${PRIMARY_REGION}"
        python3 /work/discovery/control_tower_regions.py || true

        echo ""
    fi
fi

# Phase 2: Terraform Init
echo ""
echo "============================================"
echo "  Phase 2: Terraform Init"
echo "============================================"
echo ""

cd /work/terraform

# Clear local Terraform state to prevent stale backend config
rm -rf .terraform .terraform.lock.hcl

# Initialize Terraform with S3 backend
# Check if state file exists in the bucket
echo -e "${YELLOW}Initializing Terraform...${NC}"
STATE_EXISTS=$(aws s3api head-object --bucket "${STATE_BUCKET}" --key "${STATE_KEY}" 2>/dev/null && echo "true" || echo "false")

if [ "${STATE_EXISTS}" = "true" ]; then
    # State exists, use normal init
    terraform init -input=false \
        -backend-config="bucket=${STATE_BUCKET}" \
        -backend-config="key=${STATE_KEY}" \
        -backend-config="region=${STATE_REGION}" \
        -backend-config="encrypt=true"
else
    # No state yet, use reconfigure for fresh initialization
    terraform init -input=false -reconfigure \
        -backend-config="bucket=${STATE_BUCKET}" \
        -backend-config="key=${STATE_KEY}" \
        -backend-config="region=${STATE_REGION}" \
        -backend-config="encrypt=true"
fi

# Sync bootstrap resources into Terraform state
# Uses Python script for more robust handling of edge cases
echo ""
echo -e "${YELLOW}Syncing Terraform state with existing resources...${NC}"
python3 /work/discovery/state_sync.py

# Phase 3: Terraform Plan/Apply
echo ""
echo "============================================"
echo "  Phase 3: Terraform ${TF_ACTION}"
echo "============================================"
echo ""

echo -e "${YELLOW}Running terraform ${TF_ACTION}...${NC}"
terraform ${TF_ACTION} ${TERRAFORM_ARGS}

# Phase 4: Post-Plan Preview (plan mode only)
if [ "$TF_ACTION" = "plan" ]; then
    # Check if Config S3 bucket exists (indicates previous apply) or Control Tower is detected
    CONFIG_BUCKET_EXISTS=$(terraform output -raw config_s3_bucket 2>/dev/null || echo "")
    CONTROL_TOWER_EXISTS=$(jq -r '.control_tower_exists // false' /work/terraform/discovery.json 2>/dev/null || echo "false")

    if [ -n "$CONFIG_BUCKET_EXISTS" ] || [ "$CONTROL_TOWER_EXISTS" = "true" ]; then
        echo ""
        echo "============================================"
        echo "  Phase 4: Config Enablement Preview"
        echo "============================================"
        echo ""
        echo -e "${YELLOW}Checking Config status (dry-run)...${NC}"
        python3 /work/post-deployment/enable-config-member-accounts.py --dry-run || true
        echo ""
    fi

    # Inspector member enrollment preview
    # Get audit account ID from discovery JSON or Terraform output
    AUDIT_ACCOUNT_ID=$(jq -r '.shared_accounts.audit_account_id // empty' /work/terraform/discovery.json 2>/dev/null)
    if [ -z "$AUDIT_ACCOUNT_ID" ]; then
        AUDIT_ACCOUNT_ID=$(cd /work/terraform && terraform output -raw audit_account 2>/dev/null) || true
    fi

    if [ -n "$AUDIT_ACCOUNT_ID" ]; then
        echo ""
        echo "============================================"
        echo "  Phase 4: Inspector Member Enrollment Preview"
        echo "============================================"
        echo ""
        echo -e "${YELLOW}Checking Inspector enrollment status (dry-run)...${NC}"
        python3 /work/post-deployment/enroll-inspector-members.py --audit-account-id "$AUDIT_ACCOUNT_ID" || true
        echo ""
    fi

    # GuardDuty organization configuration preview
    echo ""
    echo "============================================"
    echo "  Phase 4: GuardDuty Organization Preview"
    echo "============================================"
    echo ""
    echo -e "${YELLOW}Verifying GuardDuty organization configuration...${NC}"
    python3 /work/post-deployment/verify-guardduty.py || true
    echo ""
fi

# Phase 4: Post-Deployment (apply mode only)
if [ "$TF_ACTION" = "apply -auto-approve" ]; then
    echo ""
    echo "============================================"
    echo "  Phase 4: Post-Deployment"
    echo "============================================"
    echo ""

    # Verify deployment
    echo -e "${YELLOW}Verifying deployment...${NC}"
    python3 /work/post-deployment/verify.py || true
    VERIFY_EXIT_CODE=$?

    if [ $VERIFY_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}Deployment verification completed${NC}"
    else
        echo -e "${YELLOW}Warning: Deployment verification encountered issues (exit code: $VERIFY_EXIT_CODE)${NC}"
    fi
    echo ""

    # Cleanup default VPCs across all accounts
    echo -e "${YELLOW}Cleaning up default VPCs across all accounts...${NC}"
    python3 /work/post-deployment/cleanup-default-vpcs.py || true
    CLEANUP_EXIT_CODE=$?

    if [ $CLEANUP_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}Default VPC cleanup completed successfully${NC}"
    else
        echo -e "${YELLOW}Warning: Default VPC cleanup encountered issues (exit code: $CLEANUP_EXIT_CODE)${NC}"
        echo -e "${YELLOW}This may indicate running instances or other dependencies in default VPCs${NC}"
    fi
    echo ""

    # Enable Config recorders
    # - Standard mode: configures member accounts
    # - Control Tower mode: configures management account (CT manages all others)
    echo -e "${YELLOW}Enabling AWS Config...${NC}"
    python3 /work/post-deployment/enable-config-member-accounts.py || true
    CONFIG_EXIT_CODE=$?

    if [ $CONFIG_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}Config enablement completed successfully${NC}"
    else
        echo -e "${YELLOW}Warning: Config enablement encountered issues (exit code: $CONFIG_EXIT_CODE)${NC}"
    fi
    echo ""

    # Enroll existing member accounts in Inspector
    # Try to get audit account ID from discovery JSON first, then from Terraform output
    # (for fresh orgs, the account is created by Terraform so discovery won't have it)
    AUDIT_ACCOUNT_ID=$(jq -r '.shared_accounts.audit_account_id // empty' /work/terraform/discovery.json 2>/dev/null)
    if [ -z "$AUDIT_ACCOUNT_ID" ]; then
        # Try Terraform output (for fresh orgs where audit account was just created)
        AUDIT_ACCOUNT_ID=$(cd /work/terraform && terraform output -raw audit_account 2>/dev/null) || true
    fi

    if [ -n "$AUDIT_ACCOUNT_ID" ]; then
        echo -e "${YELLOW}Enrolling member accounts in Inspector...${NC}"
        python3 /work/post-deployment/enroll-inspector-members.py --audit-account-id "$AUDIT_ACCOUNT_ID" --apply || true
        INSPECTOR_EXIT_CODE=$?

        if [ $INSPECTOR_EXIT_CODE -eq 0 ]; then
            echo -e "${GREEN}Inspector member enrollment completed successfully${NC}"
        else
            echo -e "${YELLOW}Warning: Inspector enrollment encountered issues (exit code: $INSPECTOR_EXIT_CODE)${NC}"
        fi
        echo ""
    else
        echo -e "${YELLOW}Skipping Inspector enrollment (audit account ID not found)${NC}"
        echo ""
    fi

    # Verify GuardDuty organization configuration
    echo -e "${YELLOW}Verifying GuardDuty organization configuration...${NC}"
    python3 /work/post-deployment/verify-guardduty.py || true
    GUARDDUTY_EXIT_CODE=$?

    if [ $GUARDDUTY_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}GuardDuty organization verification completed successfully${NC}"
    else
        echo -e "${YELLOW}Warning: GuardDuty verification encountered issues (exit code: $GUARDDUTY_EXIT_CODE)${NC}"
    fi
    echo ""
fi

# Phase 5: Summary
if [ "$TF_ACTION" = "apply -auto-approve" ]; then
    echo ""
    echo "============================================"
    echo "  Phase 5: Summary"
    echo "============================================"
    echo ""
    terraform output -json organization_summary 2>/dev/null | jq . || echo "No summary output available"
    echo ""
    echo -e "${GREEN}Organization baseline deployment complete!${NC}"
fi
