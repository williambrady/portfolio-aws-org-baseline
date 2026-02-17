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
    VPC_BLOCK_MODE_SOURCE="environment"
    echo -e "${BLUE}Using VPC_BLOCK_MODE from environment: ${VPC_BLOCK_MODE}${NC}"
else
    VPC_BLOCK_MODE_SOURCE="config.yaml"
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

# Parse command line arguments (needed early for artifact timestamp)
ACTION="${1:-apply}"
TERRAFORM_ARGS="${@:2}"

# Artifact collection setup
DEPLOY_TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
ARTIFACT_TIMESTAMP=$(date -u +"%Y/%m/%d/%H%M%S-portfolio-aws-org-baseline")
ARTIFACT_DIR="/tmp/artifacts"
mkdir -p "${ARTIFACT_DIR}"
ARTIFACTS_BUCKET="${RESOURCE_PREFIX}-deployment-artifacts-${ACCOUNT_ID}"

# Deployment logging to CloudWatch Logs (always enabled)
# Log group is managed by Terraform (aws_cloudwatch_log_group.deployments)
CW_LOG_GROUP="/${RESOURCE_PREFIX}/deployments"
CW_LOG_PREFIX="${DEPLOY_TIMESTAMP}"
CW_INITIAL_STREAM="${CW_LOG_PREFIX}/config"
echo -e "${YELLOW}Streaming deployment logs to CloudWatch Logs${NC}"
echo -e "${BLUE}  Log group:  ${CW_LOG_GROUP}${NC}"
echo -e "${BLUE}  Log prefix: ${CW_LOG_PREFIX}/${NC}"

# Ensure log group exists before Terraform runs (idempotent)
# Terraform is the source of truth for retention and tags
aws logs create-log-group --log-group-name "${CW_LOG_GROUP}" \
    --region "${PRIMARY_REGION}" 2>/dev/null || true
aws logs create-log-stream --log-group-name "${CW_LOG_GROUP}" \
    --log-stream-name "${CW_INITIAL_STREAM}" \
    --region "${PRIMARY_REGION}" 2>/dev/null || true

CW_FIFO="/tmp/cw-fifo-$$"
mkfifo "${CW_FIFO}"
python3 /work/discovery/cloudwatch_logger.py \
    "${CW_LOG_GROUP}" "${CW_INITIAL_STREAM}" "${PRIMARY_REGION}" < "${CW_FIFO}" &
CW_LOGGER_PID=$!
exec 3>"${CW_FIFO}"

# Helper to tee output to artifact file and optionally CloudWatch Logs.
# Usage: some_command 2>&1 | tee_log <artifact_file> <phase>
# The phase is used to create a separate CloudWatch log stream per phase.
tee_log() {
    local artifact_file="${ARTIFACT_DIR}/$1"
    local phase="${2:-}"
    if [ -n "${CW_LOGGER_PID}" ] && kill -0 "${CW_LOGGER_PID}" 2>/dev/null; then
        if [ -n "${phase}" ]; then
            # Leading newline ensures the sentinel starts on a fresh line even
            # if the previous writer (e.g. tee of a JSON file) did not emit a
            # trailing newline. The logger skips blank lines, so this is safe.
            printf '\n###STREAM:%s\n' "${CW_LOG_PREFIX}/${phase}" >&3
        fi
        tee "${artifact_file}" /dev/fd/3
    else
        tee "${artifact_file}"
    fi
}

# EXIT trap to upload artifacts and clean up CloudWatch logger on any exit
upload_artifacts() {
    local exit_code=$?

    # Close CloudWatch logger
    if [ -n "${CW_LOGGER_PID}" ]; then
        exec 3>&- 2>/dev/null || true
        wait "${CW_LOGGER_PID}" 2>/dev/null || true
        rm -f "${CW_FIFO}" 2>/dev/null || true
    fi

    # Upload artifacts to S3
    if aws s3api head-bucket --bucket "${ARTIFACTS_BUCKET}" 2>/dev/null; then
        echo -e "${YELLOW}Uploading deployment artifacts...${NC}"
        aws s3 cp "${ARTIFACT_DIR}/" "s3://${ARTIFACTS_BUCKET}/${ARTIFACT_TIMESTAMP}/" \
            --recursive --quiet 2>/dev/null || true
        echo -e "${GREEN}Artifacts uploaded to s3://${ARTIFACTS_BUCKET}/${ARTIFACT_TIMESTAMP}/${NC}"
    fi
    exit $exit_code
}
trap upload_artifacts EXIT

# Capture runtime configuration as the first artifact/log stream
{
    echo "Runtime Configuration"
    echo "=================================================="
    echo ""
    echo "Timestamp:      $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Action:         ${ACTION}"
    echo "Account ID:     ${ACCOUNT_ID}"
    echo "Caller ARN:     ${CALLER_ARN}"
    echo "Terraform Args: ${TERRAFORM_ARGS:-<none>}"
    echo ""
    echo "Effective Settings:"
    echo "  resource_prefix:    ${RESOURCE_PREFIX}"
    echo "  primary_region:     ${PRIMARY_REGION}"
    echo "  vpc_block_mode:     ${VPC_BLOCK_MODE} (source: ${VPC_BLOCK_MODE_SOURCE})"
    echo ""
    echo "Runtime Flags:"
    echo "  SKIP_VPC_CLEANUP:   ${SKIP_VPC_CLEANUP:-<not set>}"
    echo ""
    echo "config.yaml:"
    echo "=================================================="
    cat /work/config.yaml
    echo ""
    echo "=================================================="
} 2>&1 | tee_log "config.log" "config"
cp /work/config.yaml "${ARTIFACT_DIR}/" 2>/dev/null || true

# State bucket configuration
STATE_BUCKET="${RESOURCE_PREFIX}-tfstate-${ACCOUNT_ID}"
STATE_KEY="organization/terraform.tfstate"
STATE_REGION="${PRIMARY_REGION}"

# -----------------------------------------------------------------------------
# Bootstrap Helper Functions
# -----------------------------------------------------------------------------

# Creates a KMS key with alias if it doesn't exist.
# Sets KMS_KEY_ARN_RESULT to the key ARN on return.
bootstrap_kms_key() {
    local alias_name="$1"
    local description="$2"
    local protected_bucket="$3"

    KMS_KEY_ARN_RESULT=""

    # Check if alias already exists
    if aws kms describe-key --key-id "alias/${alias_name}" --region "${STATE_REGION}" >/dev/null 2>&1; then
        local key_id
        key_id=$(aws kms describe-key \
            --key-id "alias/${alias_name}" \
            --region "${STATE_REGION}" \
            --query 'KeyMetadata.KeyId' \
            --output text)
        KMS_KEY_ARN_RESULT="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${key_id}"
        echo -e "${GREEN}KMS key alias/${alias_name} exists (${key_id})${NC}"
        return 0
    fi

    echo -e "${YELLOW}Creating KMS key: alias/${alias_name}${NC}"
    local key_id
    key_id=$(aws kms create-key \
        --description "${description}" \
        --tags TagKey=Name,TagValue=${alias_name}-key \
               TagKey=Purpose,TagValue="S3 bucket encryption" \
               TagKey=ProtectsBucket,TagValue="${protected_bucket}" \
               TagKey=ManagedBy,TagValue=portfolio-aws-org-baseline \
        --region "${STATE_REGION}" \
        --query 'KeyMetadata.KeyId' \
        --output text \
        --no-cli-pager)

    aws kms create-alias \
        --alias-name "alias/${alias_name}" \
        --target-key-id "${key_id}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    aws kms enable-key-rotation \
        --key-id "${key_id}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    KMS_KEY_ARN_RESULT="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${key_id}"
    echo -e "${GREEN}Created KMS key: alias/${alias_name} (${key_id})${NC}"
}

# Creates an S3 bucket if it doesn't exist.
# Configures versioning, KMS encryption, public access block, SSL policy, and optionally access logging.
bootstrap_s3_bucket() {
    local bucket_name="$1"
    local kms_key_arn="$2"
    local access_logs_bucket="${3:-}"

    if aws s3api head-bucket --bucket "${bucket_name}" 2>/dev/null; then
        echo -e "${GREEN}S3 bucket ${bucket_name} exists${NC}"
        return 0
    fi

    echo -e "${YELLOW}Creating S3 bucket: ${bucket_name}${NC}"

    # Create bucket (us-east-1 doesn't use LocationConstraint)
    if [ "${STATE_REGION}" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "${bucket_name}" \
            --region "${STATE_REGION}" \
            --no-cli-pager
    else
        aws s3api create-bucket \
            --bucket "${bucket_name}" \
            --region "${STATE_REGION}" \
            --create-bucket-configuration LocationConstraint="${STATE_REGION}" \
            --no-cli-pager
    fi

    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "${bucket_name}" \
        --versioning-configuration Status=Enabled \
        --no-cli-pager

    # Enable KMS encryption
    aws s3api put-bucket-encryption \
        --bucket "${bucket_name}" \
        --server-side-encryption-configuration "{
            \"Rules\": [{
                \"ApplyServerSideEncryptionByDefault\": {
                    \"SSEAlgorithm\": \"aws:kms\",
                    \"KMSMasterKeyID\": \"${kms_key_arn}\"
                },
                \"BucketKeyEnabled\": true
            }]
        }" \
        --no-cli-pager

    # Block public access
    aws s3api put-public-access-block \
        --bucket "${bucket_name}" \
        --public-access-block-configuration '{
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
        }' \
        --no-cli-pager

    # Add bucket policy for SSL enforcement
    aws s3api put-bucket-policy \
        --bucket "${bucket_name}" \
        --policy "{
            \"Version\": \"2012-10-17\",
            \"Statement\": [
                {
                    \"Sid\": \"DenyNonSSL\",
                    \"Effect\": \"Deny\",
                    \"Principal\": \"*\",
                    \"Action\": \"s3:*\",
                    \"Resource\": [
                        \"arn:aws:s3:::${bucket_name}\",
                        \"arn:aws:s3:::${bucket_name}/*\"
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

    # Configure access logging if a target bucket is provided
    if [ -n "${access_logs_bucket}" ]; then
        aws s3api put-bucket-logging \
            --bucket "${bucket_name}" \
            --bucket-logging-status "{
                \"LoggingEnabled\": {
                    \"TargetBucket\": \"${access_logs_bucket}\",
                    \"TargetPrefix\": \"${bucket_name}/\"
                }
            }" \
            --no-cli-pager
    fi

    echo -e "${GREEN}Created S3 bucket: ${bucket_name}${NC}"
}

# Step 1: Bootstrap - create KMS keys and S3 buckets
echo -e "${YELLOW}Bootstrapping infrastructure...${NC}"
{
    ACCESS_LOGS_BUCKET="${RESOURCE_PREFIX}-access-logs-${ACCOUNT_ID}"

    # 1. Access logs KMS key + bucket (must be first - other buckets log to it)
    bootstrap_kms_key "${RESOURCE_PREFIX}-access-logs" \
        "KMS key for S3 access logs bucket encryption" \
        "${ACCESS_LOGS_BUCKET}"
    KMS_ACCESS_LOGS_ARN="${KMS_KEY_ARN_RESULT}"

    bootstrap_s3_bucket "${ACCESS_LOGS_BUCKET}" "${KMS_ACCESS_LOGS_ARN}"
    # Access logs bucket needs BucketOwnerPreferred for S3 log delivery
    aws s3api put-bucket-ownership-controls \
        --bucket "${ACCESS_LOGS_BUCKET}" \
        --ownership-controls '{"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}' \
        --no-cli-pager 2>/dev/null || true

    # 2. Terraform state KMS key + bucket
    bootstrap_kms_key "${RESOURCE_PREFIX}-tfstate" \
        "KMS key for Terraform state bucket encryption" \
        "${STATE_BUCKET}"
    KMS_TFSTATE_ARN="${KMS_KEY_ARN_RESULT}"

    bootstrap_s3_bucket "${STATE_BUCKET}" "${KMS_TFSTATE_ARN}" "${ACCESS_LOGS_BUCKET}"

    # 3. Deployment artifacts KMS key + bucket
    bootstrap_kms_key "${RESOURCE_PREFIX}-deployment-artifacts" \
        "KMS key for deployment artifacts bucket encryption" \
        "${ARTIFACTS_BUCKET}"
    KMS_ARTIFACTS_ARN="${KMS_KEY_ARN_RESULT}"

    bootstrap_s3_bucket "${ARTIFACTS_BUCKET}" "${KMS_ARTIFACTS_ARN}" "${ACCESS_LOGS_BUCKET}"

    echo -e "${GREEN}Bootstrap complete${NC}"
} 2>&1 | tee_log "bootstrap.log" "bootstrap"
echo ""

case "$ACTION" in
    discover)
        echo -e "${YELLOW}Running discovery only...${NC}"
        python3 /work/discovery/discover.py 2>&1 | tee_log "discover.log" "discover"
        cp /work/terraform/bootstrap.auto.tfvars.json "${ARTIFACT_DIR}/" 2>/dev/null || true
        cp /work/terraform/discovery.json "${ARTIFACT_DIR}/" 2>/dev/null || true
        cat "${ARTIFACT_DIR}/bootstrap.auto.tfvars.json" 2>/dev/null | tee_log "tfvars.json" "tfvars" || true
        cat "${ARTIFACT_DIR}/discovery.json" 2>/dev/null | tee_log "discovery-data.json" "discovery-data" || true
        exit 0
        ;;
    shell)
        echo -e "${YELLOW}Opening interactive shell...${NC}"
        exec /bin/bash
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
        echo "Usage: $0 [discover|plan|apply|destroy|shell]"
        exit 1
        ;;
esac

# Phase 1: Discovery
echo ""
echo "============================================"
echo "  Phase 1: Discovery"
echo "============================================"
echo ""
python3 /work/discovery/discover.py 2>&1 | tee_log "discover.log" "discover"
cp /work/terraform/bootstrap.auto.tfvars.json "${ARTIFACT_DIR}/" 2>/dev/null || true
cp /work/terraform/discovery.json "${ARTIFACT_DIR}/" 2>/dev/null || true
cat "${ARTIFACT_DIR}/bootstrap.auto.tfvars.json" 2>/dev/null | tee_log "tfvars.json" "tfvars" || true
cat "${ARTIFACT_DIR}/discovery.json" 2>/dev/null | tee_log "discovery-data.json" "discovery-data" || true
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
        python3 /work/discovery/control_tower_regions.py 2>&1 | tee_log "control-tower.log" "control-tower" || true

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

{
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
} 2>&1 | tee_log "init.log" "init"

# Sync bootstrap resources into Terraform state
# Uses Python script for more robust handling of edge cases
echo ""
echo -e "${YELLOW}Syncing Terraform state with existing resources...${NC}"
python3 /work/discovery/state_sync.py 2>&1 | tee_log "import.log" "import"

# Phase 3: Terraform Plan/Apply
echo ""
echo "============================================"
echo "  Phase 3: Terraform ${TF_ACTION}"
echo "============================================"
echo ""

echo -e "${YELLOW}Running terraform ${TF_ACTION}...${NC}"
terraform ${TF_ACTION} ${TERRAFORM_ARGS} 2>&1 | tee_log "${TF_ACTION%% *}.log" "${TF_ACTION%% *}"

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
        python3 /work/post-deployment/enable-config-member-accounts.py --dry-run 2>&1 | tee_log "enable-config.log" "enable-config" || true
        echo ""
    fi

    # VPC cleanup preview
    if [ "${SKIP_VPC_CLEANUP:-}" != "true" ]; then
        echo ""
        echo "============================================"
        echo "  Phase 4: Default VPC Cleanup Preview"
        echo "============================================"
        echo ""
        echo -e "${YELLOW}Checking default VPC status (dry-run)...${NC}"
        python3 /work/post-deployment/cleanup-default-vpcs.py --dry-run 2>&1 | tee_log "cleanup-vpcs.log" "cleanup-vpcs" || true
        echo ""
    else
        echo ""
        echo -e "${YELLOW}Skipping VPC cleanup preview (SKIP_VPC_CLEANUP=true)${NC}"
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
        python3 /work/post-deployment/enroll-inspector-members.py --audit-account-id "$AUDIT_ACCOUNT_ID" 2>&1 | tee_log "enroll-inspector.log" "enroll-inspector" || true
        echo ""
    fi

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
    python3 /work/post-deployment/verify.py 2>&1 | tee_log "verify.log" "verify" || true
    VERIFY_EXIT_CODE=$?

    if [ $VERIFY_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}Deployment verification completed${NC}"
    else
        echo -e "${YELLOW}Warning: Deployment verification encountered issues (exit code: $VERIFY_EXIT_CODE)${NC}"
    fi
    echo ""

    # Cleanup default VPCs across all accounts
    if [ "${SKIP_VPC_CLEANUP:-}" != "true" ]; then
        echo -e "${YELLOW}Cleaning up default VPCs across all accounts...${NC}"
        python3 /work/post-deployment/cleanup-default-vpcs.py 2>&1 | tee_log "cleanup-vpcs.log" "cleanup-vpcs" || true
        CLEANUP_EXIT_CODE=$?

        if [ $CLEANUP_EXIT_CODE -eq 0 ]; then
            echo -e "${GREEN}Default VPC cleanup completed successfully${NC}"
        else
            echo -e "${YELLOW}Warning: Default VPC cleanup encountered issues (exit code: $CLEANUP_EXIT_CODE)${NC}"
            echo -e "${YELLOW}This may indicate running instances or other dependencies in default VPCs${NC}"
        fi
        echo ""
    else
        echo -e "${YELLOW}Skipping VPC cleanup (SKIP_VPC_CLEANUP=true)${NC}"
        echo ""
    fi

    # Enable Config recorders
    # - Standard mode: configures member accounts
    # - Control Tower mode: configures management account (CT manages all others)
    echo -e "${YELLOW}Enabling AWS Config...${NC}"
    python3 /work/post-deployment/enable-config-member-accounts.py 2>&1 | tee_log "enable-config.log" "enable-config" || true
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
        python3 /work/post-deployment/enroll-inspector-members.py --audit-account-id "$AUDIT_ACCOUNT_ID" --apply 2>&1 | tee_log "enroll-inspector.log" "enroll-inspector" || true
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

fi

# Phase 5: Summary
if [ "$TF_ACTION" = "apply -auto-approve" ]; then
    echo ""
    echo "============================================"
    echo "  Phase 5: Summary"
    echo "============================================"
    echo ""
    terraform output -json organization_summary 2>/dev/null | jq . | tee_log "summary.json" "summary" || echo "No summary output available"
    echo ""
    echo -e "${GREEN}Organization baseline deployment complete!${NC}"
fi
