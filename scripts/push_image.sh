#!/bin/bash
set -e

REGION=$1
REPO_URL=$2
LOG_FILE="${PWD}/ecr_push.log"

exec > >(tee -a "$LOG_FILE") 2>&1

echo "Starting ECR push process at $(date)"
echo "Region: $REGION"
echo "Repository URL: $REPO_URL"

echo "Logging in to ECR..."
if aws ecr get-login-password --region $REGION --profile fmoralesIsolated | docker login --username AWS --password-stdin $REPO_URL; then
    echo "Successfully logged in to ECR"
else
    echo "Failed to log in to ECR"
    exit 1
fi

echo "Creating Dockerfile..."
echo "FROM --platform=linux/amd64 nginx:1.27.0-alpine-slim" > Dockerfile

echo "Setting up Docker buildx..."
if docker buildx create --use --name mybuilder; then
    echo "Docker buildx setup successful"
else
    echo "Failed to set up Docker buildx"
    exit 1
fi

echo "Building and loading Docker image..."
if docker buildx build --platform linux/amd64 -t ${REPO_URL}:1.27.0-alpine-slim . --load; then
    echo "Docker image built and loaded successfully"
else
    echo "Failed to build and load Docker image"
    exit 1
fi

echo "Pushing Docker image..."
if docker push ${REPO_URL}:1.27.0-alpine-slim; then
    echo "Docker image pushed successfully"
else
    echo "Failed to push Docker image"
    exit 1
fi

echo "Cleaning up..."
rm Dockerfile
docker buildx rm mybuilder

echo "ECR push process completed at $(date)"
