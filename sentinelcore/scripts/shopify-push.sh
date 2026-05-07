#!/usr/bin/env bash
# Push Shopify theme files to the live store via Admin REST API.
# Requires env vars: SHOPIFY_ADMIN_TOKEN, SHOPIFY_THEME_ID, SHOPIFY_STORE
set -euo pipefail

STORE="${SHOPIFY_STORE:-redgaurd.myshopify.com}"
THEME_ID="${SHOPIFY_THEME_ID}"
TOKEN="${SHOPIFY_ADMIN_TOKEN}"
API="https://${STORE}/admin/api/2024-01/themes/${THEME_ID}/assets.json"

push_asset() {
  local shopify_key="$1"   # e.g. templates/page.homepage.liquid
  local local_file="$2"    # path in repo

  echo "  Pushing $shopify_key ..."
  local value
  value=$(cat "$local_file")

  local response
  response=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API" \
    -H "X-Shopify-Access-Token: ${TOKEN}" \
    -H "Content-Type: application/json" \
    --data-binary "$(jq -n --arg k "$shopify_key" --arg v "$value" \
      '{asset:{key:$k,value:$v}}')")

  if [[ "$response" == "200" || "$response" == "201" ]]; then
    echo "    OK ($response)"
  else
    echo "    FAILED ($response)"
    exit 1
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SHOPIFY_DIR="$REPO_ROOT/sentinelcore/shopify"

echo "==> Deploying Shopify theme assets to $STORE (theme $THEME_ID)"

push_asset "templates/page.homepage.liquid" "$SHOPIFY_DIR/homepage.liquid"

echo "==> Done."
