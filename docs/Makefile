# Docker image settings
IMAGE_NAME ?= policyengine-docs
IMAGE_TAG ?= latest
CONTAINER_NAME ?= policyengine-docs
PORT ?= 8080

.PHONY: build start clean install lint spellcheck typecheck \
        docker-build docker-run docker-stop docker-clean docker-logs docker-shell docker-restart docker-status

all: build

# --- Local Development Targets ---

# Install npm dependencies
install:
	npm ci

# Build the Docusaurus site
build: install
	npm run build

# Start local development server
start: install
	npm start

# Clean local build artifacts
clean:
	-npm run clear
	-rm -rf node_modules
	-rm -rf build

# --- Documentation Validation Targets ---

# Run TypeScript type checking
typecheck: install
	npm run typecheck

# Run spell checking on documentation
spellcheck: install
	npm run spellcheck

# Run all linting and validation (typecheck, spellcheck, and build for link validation)
lint: install
	npm run lint

# --- Docker Targets ---

# Build the Docker image
docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run the container
docker-run: docker-build
	docker run -d --name $(CONTAINER_NAME) -p $(PORT):80 $(IMAGE_NAME):$(IMAGE_TAG)
	@echo "Documentation is available at http://localhost:$(PORT)/policyengine/"

# Stop and remove the container
docker-stop:
	-docker stop $(CONTAINER_NAME)
	-docker rm $(CONTAINER_NAME)

# Remove the Docker image
docker-clean: docker-stop
	-docker rmi $(IMAGE_NAME):$(IMAGE_TAG)

# View container logs
docker-logs:
	docker logs -f $(CONTAINER_NAME)

# Open a shell in the running container
docker-shell:
	docker exec -it $(CONTAINER_NAME) /bin/sh

# Restart the container
docker-restart: docker-stop docker-run

# Show container status
docker-status:
	@docker ps -a --filter name=$(CONTAINER_NAME) --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
