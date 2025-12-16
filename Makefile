# Copyright Manetu Inc. All Rights Reserved.

PROJECT_NAME := manetu-go-policyengine
OUTPUTDIR := target

.PHONY: all clean test goimports staticcheck tests sec-scan protos

all: test test_fips race staticcheck goimports sec-scan

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
