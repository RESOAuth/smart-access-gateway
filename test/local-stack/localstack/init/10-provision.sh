#!/bin/bash
# Provision the AWS side of the local stack.
#
# LocalStack runs every executable in /etc/localstack/init/ready.d once the
# services it is emulating are up, so this is the stack's equivalent of the
# Terraform an operator would run before their first deployment: a signing key,
# a table, and a bucket with the relying party records in it.
#
# Nothing here is SAG-specific plumbing. It is the same three resources
# docs/deployment.md asks for on AWS, which is what makes the Lambda instance
# in this stack a real rehearsal rather than a demonstration.
set -euo pipefail

# Version 1 of the AWS CLI is what this image ships, and it has no
# --no-cli-pager flag. Emptying the pager is the portable way to say it.
export AWS_PAGER=""

REGION="${AWS_DEFAULT_REGION:-eu-west-2}"
TABLE="${SAG_STATE_TABLE:-sag-state}"
BUCKET="${SAG_CLIENTS_BUCKET:-sag-clients}"
ALIAS="alias/sag-signing"

echo "[sag] provisioning in ${REGION}"

# --- The signing key -------------------------------------------------------
#
# ECC_NIST_P256 with SIGN_VERIFY is what SIGNING_ALG=ES256 needs. The alias is
# the point: SAG is configured with alias/sag-signing rather than a key id, so
# nothing has to be pasted between containers, and rotating the key underneath
# an alias is the migration path a real deployment would use.
KEY_ID="$(awslocal kms create-key \
  --key-spec ECC_NIST_P256 \
  --key-usage SIGN_VERIFY \
  --description 'SAG local stack id_token signing key' \
  --query 'KeyMetadata.KeyId' --output text)"
awslocal kms create-alias --alias-name "${ALIAS}" --target-key-id "${KEY_ID}"
echo "[sag] KMS ${ALIAS} -> ${KEY_ID}"

# --- Single-use codes and OTP send limits ----------------------------------
#
# One hash key, and a TTL attribute so DynamoDB clears the records itself.
# SAG's condition expressions do not trust the TTL to be prompt - AWS only
# promises within 48 hours - which is why the table needs nothing else.
awslocal dynamodb create-table \
  --table-name "${TABLE}" \
  --attribute-definitions AttributeName=jti,AttributeType=S \
  --key-schema AttributeName=jti,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST >/dev/null
awslocal dynamodb update-time-to-live \
  --table-name "${TABLE}" \
  --time-to-live-specification 'Enabled=true,AttributeName=expires_at' >/dev/null
echo "[sag] DynamoDB table ${TABLE} ready"

# --- The relying party register --------------------------------------------
#
# One JSON object per client id under clients/, which is the layout
# CLIENTS_STORE_PREFIX defaults to. Records are copied in rather than mounted,
# so editing one on the host and re-running this script is the same operation
# as an operator updating a record in their bucket.
awslocal s3 mb "s3://${BUCKET}" >/dev/null
if compgen -G '/etc/localstack/seed/clients/*.json' >/dev/null; then
  awslocal s3 cp --recursive --no-progress \
    /etc/localstack/seed/clients "s3://${BUCKET}/clients" >/dev/null
  echo "[sag] S3 ${BUCKET} seeded with $(ls -1 /etc/localstack/seed/clients/*.json | wc -l) client record(s)"
else
  echo "[sag] S3 ${BUCKET} created, but there were no client records to seed"
fi

echo "[sag] provisioning done"
