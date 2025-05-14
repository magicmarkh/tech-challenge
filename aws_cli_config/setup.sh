#!/bin/bash
sudo yum install -y file
set -e

echo "➡ Fetching latest Terraform version..."
LATEST=$(curl -s https://checkpoint-api.hashicorp.com/v1/check/terraform | grep -oP '"current_version":"\K[0-9]+\.[0-9]+\.[0-9]+')

DOWNLOAD_URL="https://releases.hashicorp.com/terraform/${LATEST}/terraform_${LATEST}_linux_amd64.zip"

echo "➡ Downloading Terraform ${LATEST} from ${DOWNLOAD_URL}..."
curl -fL -o terraform_${LATEST}_linux_amd64.zip ${DOWNLOAD_URL}

echo "➡ Validating downloaded file..."
if file terraform_${LATEST}_linux_amd64.zip | grep -q 'Zip archive data'; then
    echo "✅ Valid zip detected."
    unzip -o terraform_${LATEST}_linux_amd64.zip
    sudo mv terraform /usr/local/bin/
    terraform version
else
    echo "❌ Download failed or invalid file. Aborting."
    rm -f terraform_${LATEST}_linux_amd64.zip
    exit 1
fi