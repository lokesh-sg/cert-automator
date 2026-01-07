#!/bin/bash

# CertAutomator - Distribution & Export Script
# This script builds the production Docker image and exports it to a portable .tar file.

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 Starting CertAutomator Packaging...${NC}"

# 1. Build and Export AMD64 (Intel/AMD)
echo -e "${BLUE}🔨 Step 1: Building image for AMD64 (Intel/AMD)...${NC}"
docker buildx build --platform linux/amd64 -t cert-automator:amd64 --load ./prod
docker save cert-automator:amd64 > cert-automator-amd64.tar

# 2. Build and Export ARM64 (Apple Silicon/Raspberry Pi)
echo -e "${BLUE}🔨 Step 2: Building image for ARM64 (Apple Silicon/ARM)...${NC}"
docker buildx build --platform linux/arm64 -t cert-automator:arm64 --load ./prod
docker save cert-automator:arm64 > cert-automator-arm64.tar

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Build and Export successful!${NC}"
    echo -e "Created: cert-automator-amd64.tar"
    echo -e "Created: cert-automator-arm64.tar"
else
    echo "❌ Build failed. Please ensure Docker is running."
    exit 1
fi

# 3. Registry Push (Optional)
echo -e ""
read -p "Do you want to push this image to a Docker Registry (e.g. Docker Hub)? (y/n): " PUSH_CHOICE
if [[ "$PUSH_CHOICE" == "y" || "$PUSH_CHOICE" == "Y" ]]; then
    read -p "Enter your Docker repository name [default: lokeshsg/cert-automator]: " REPO_NAME
    REPO_NAME=${REPO_NAME:-lokeshsg/cert-automator}
    if [[ -z "$REPO_NAME" ]]; then
        echo -e "${BLUE}❌ Repository name cannot be empty. Skipping push.${NC}"
    else
        echo -e "${BLUE}🚀 Step 3: Building and Pushing Universal Image to $REPO_NAME...${NC}"
        
        # Extract Version
        MAJOR=$(grep -o '"major": [0-9]*' build_scripts/version_info.json | awk '{print $2}')
        MINOR=$(grep -o '"minor": [0-9]*' build_scripts/version_info.json | awk '{print $2}')
        BUILD=$(grep -o '"build": [0-9]*' build_scripts/version_info.json | awk '{print $2}')
        VERSION_TAG="v${MAJOR}.${MINOR}.0_build${BUILD}"
        
        echo -e "${BLUE}🏷️  Tags: latest, ${VERSION_TAG}${NC}"

        # Setting up builder if not already set
        docker buildx create --name cert-builder --use 2>/dev/null || docker buildx use cert-builder

        
        # Build and Push multi-arch directly to registry
        docker buildx build --platform linux/amd64,linux/arm64 \
          --attest type=provenance,mode=max \
          --attest type=sbom \
          -t "$REPO_NAME:latest" \
          -t "$REPO_NAME:$VERSION_TAG" \
          --push ./prod
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Successfully pushed multi-arch image to $REPO_NAME${NC}"
        else
            echo -e "❌ Push failed. Are you logged in? (Run 'docker login')"
        fi
    fi
fi

# 4. Final instructions
echo -e "${BLUE}--------------------------------------------------${NC}"
echo -e "${GREEN}🎉 Done! Your distribution packages are ready.${NC}"
echo -e "I have created separate files for different hardware types."
echo -e ""
echo -e "To share this, send the correct .tar + docker-compose.yml:"
echo -e " - For Intel/AMD servers: cert-automator-amd64.tar"
echo -e " - For Apple Silicon/ARM: cert-automator-arm64.tar"
echo -e ""
echo -e "Or if you pushed it to a registry, just share the repository name!"
echo -e ""
echo -e "They can deploy it by running:"
echo -e "  'docker load < [filename].tar'"
echo -e "  OR 'docker pull $REPO_NAME'"
echo -e "${BLUE}--------------------------------------------------${NC}"
