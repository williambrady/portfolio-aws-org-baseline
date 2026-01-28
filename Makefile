.PHONY: build test lint discover plan apply destroy shell state-cleanup clean help

IMAGE_NAME := portfolio-aws-org-baseline
IMAGE_TAG := dev

# Optional environment variable overrides (pass to Docker if set)
# VPC_BLOCK_MODE - Override vpc_block_public_access.mode (ingress, bidirectional, disabled)
DOCKER_ENV := -e AWS_PROFILE=$(AWS_PROFILE)
ifdef VPC_BLOCK_MODE
DOCKER_ENV += -e VPC_BLOCK_MODE=$(VPC_BLOCK_MODE)
endif

# Default target
help:
	@echo "Available targets:"
	@echo "  build     - Build the Docker image"
	@echo "  discover  - Run discovery only"
	@echo "  plan      - Run discovery + Terraform plan"
	@echo "  apply     - Full deployment (discovery + apply + post-deployment)"
	@echo "  destroy   - Tear down all managed resources"
	@echo "  shell     - Open shell in container"
	@echo "  clean     - Remove Docker image"
	@echo ""
	@echo "Environment variables:"
	@echo "  AWS_PROFILE    - AWS profile to use (required)"
	@echo "  VPC_BLOCK_MODE - Override vpc_block_public_access.mode (ingress, bidirectional, disabled)"

# Build the Docker image
build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run discovery only
discover: build
	docker run --rm \
		-v "$(HOME)/.aws:/home/baseline/.aws:ro" \
		$(DOCKER_ENV) \
		$(IMAGE_NAME):$(IMAGE_TAG) discover

# Run plan (discovery + Terraform plan)
plan: build
	docker run --rm \
		-v "$(HOME)/.aws:/home/baseline/.aws:ro" \
		$(DOCKER_ENV) \
		$(IMAGE_NAME):$(IMAGE_TAG) plan

# Full deployment
apply: build
	docker run --rm \
		-v "$(HOME)/.aws:/home/baseline/.aws:ro" \
		$(DOCKER_ENV) \
		$(IMAGE_NAME):$(IMAGE_TAG) apply

# Tear down resources
destroy: build
	docker run --rm \
		-v "$(HOME)/.aws:/home/baseline/.aws:ro" \
		$(DOCKER_ENV) \
		$(IMAGE_NAME):$(IMAGE_TAG) destroy

# Open interactive shell in container
shell: build
	docker run --rm -it \
		-v "$(HOME)/.aws:/home/baseline/.aws:ro" \
		$(DOCKER_ENV) \
		--entrypoint /bin/bash \
		$(IMAGE_NAME):$(IMAGE_TAG)

# Remove old GuardDuty detectors from Terraform state (one-time migration)
state-cleanup: build
	docker run --rm \
		-v "$(HOME)/.aws:/home/baseline/.aws:ro" \
		$(DOCKER_ENV) \
		$(IMAGE_NAME):$(IMAGE_TAG) state-cleanup

# Clean up Docker image
clean:
	docker rmi $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || true
