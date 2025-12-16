# Copyright Manetu Inc. All Rights Reserved.

PROJECT_NAME := manetu-go-policyengine
BINARY_NAME := mpe
GO_FILES := $(shell find . -name '*.go')
OUTPUTDIR := target
DOCKER_IMAGE ?= ghcr.io/manetu/policyengine

.PHONY: all clean test goimports staticcheck tests sec-scan protos docker

all: test test_fips race staticcheck goimports sec-scan build

build: $(OUTPUTDIR)/$(BINARY_NAME)

$(OUTPUTDIR)/$(BINARY_NAME): $(GO_FILES) Makefile
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@mkdir -p $(OUTPUTDIR)
	@GOOS=${GOOS} GOARCH=${GOARCH} go build ${LDFLAGS} -o $@ ./cmd/mpe

docker: ## Build and publish Docker container using ko (requires DOCKER_IMAGE env var, e.g., DOCKER_IMAGE=ghcr.io/manetu/policyengine)
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@if [ -z "$(DOCKER_IMAGE)" ]; then \
		echo "Error: DOCKER_IMAGE is required (e.g., DOCKER_IMAGE=ghcr.io/manetu/policyengine)"; \
		exit 1; \
	fi
	@KO_DOCKER_REPO=$(DOCKER_IMAGE) ko build --platform=linux/amd64,linux/arm64 --bare --push github.com/manetu/policyengine/cmd/mpe

lint: ## Lint the files
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@golint -set_exit_status ./...

test: ## Run unittests
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@go test -coverpkg=./... -cover ./...

target/cover.out:
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@mkdir -p $(OUTPUTDIR)
	@go test -v -coverpkg=./... -coverprofile $@ -cover ./...

target/cover.html: target/cover.out
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@go tool cover -html $^ -o $@

coverage: target/cover.html

test_fips: ## Run unittests with FIPS enabled
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@GODEBUG=fips140=only go test -cover ./...

race: ## Run data race detector
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@go test ./... -race -short .

staticcheck: ## Run data race detector
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@staticcheck -f stylish  ./...

goimports: ## Run goimports
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	$(eval goimportsdiffs = $(shell goimports -l  $(shell find . -name '*.go' | grep -v pkg/protos)))
	@if [ -n "$(goimportsdiffs)" ]; then\
		echo "goimports shows diffs for these files:";\
		echo "$(goimportsdiffs)";\
		exit 1;\
	fi

protos:
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@buf generate

clean: ## Remove previous build
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@go clean -testcache
	-@rm -rf target

sec-scan: ## Run gosec; see https://github.com/securego/gosec
	@printf "\033[36m%-30s\033[0m %s\n" "### make $@"
	@gosec --exclude-dir=pkg/protos ./...

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
