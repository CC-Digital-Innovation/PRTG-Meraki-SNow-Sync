#!/bin/bash

# get token from vault
export VAULT_TOKEN=$(curl -X POST -d "{\"role\": \"sops\", \"jwt\": \"$(cat $JWT_PATH)\"}" "${VAULT_ADDR}/v1/auth/kubernetes/login" | jq -r .auth.client_token)

# decrypt config file
sops -d --hc-vault-transit ${VAULT_ADDR}/v1/sops/keys/test-key configs/PRTG-Meraki-SNow-Sync-config-encrypted.ini > configs/PRTG-Meraki-SNow-Sync-config.ini

# run main
python src/PRTG-Meraki-SNow-Sync.py