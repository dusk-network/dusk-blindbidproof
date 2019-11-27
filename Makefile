PKG := "gitlab.dusk.network/dusk-network/dusk-blindbidproof/blindbidproof"
PKG_LIST := $(shell go list ${PKG}/...)
RS_FILES := $(shell find . -name '*.rs')
GO_FILES := $(shell find . -name '*.go')
.PHONY: all dep lintdep lint fmt inttest test clean build release bench publishdoc
all: test inttest build release ## Main sequence
dep: ## Install the dependencies
	@rustup toolchain install beta
	@rustup toolchain install nightly
	@rustup component add rustfmt --toolchain=beta
lintdep-go: ## Get the dependencies for the lint
	@go get -u golang.org/x/lint/golint
lint-go: lintdep-go ## Lint the files
	@golint -set_exit_status ${PKG_LIST}
lintdep: dep ## Install the lint deps
	@rustup component add clippy --toolchain=nightly
lint: ## Perform the clippy lints
	@cargo +nightly clippy
fmt: ## Format the go files
	@cargo +beta fmt -- ${RS_FILES}
fmt-go: ## Format the go files
	@gofmt -w ${GO_FILES}
inttest: ## Run integration test
	@cargo +nightly test --release -- --ignored --test-threads=1
test: ## Run unittests
	@cargo +nightly check && \
		cargo +beta fmt --all -- --check && \
		cargo +nightly test
test-go: build ## Run unittests
	@./scripts/test-go.sh
clean: ## Remove previous build
	@cargo +nightly clean
build: ## Build with debug symbols
	@cargo +nightly build
release: ## Build with optimization and without debug symbols
	@cargo +nightly build --release
bench: ## Perform the benchmark tests
	@cargo +nightly bench
bench-go: release ## Perform the benchmark tests
	@./scripts/bench-go.sh
publishdoc: ## Generate and publish git pages docs
	@cargo +nightly doc && \
		echo "<meta http-equiv=refresh content=0;url=`echo 'https://dusk-network.github.io/dusk-blindbidproof/dusk_blindbidproof/index.html' | cut -d '/' -f 2`/index.html>" > target/doc/index.html && \
		curl -o 'target/doc/badge.svg' 'https://img.shields.io/badge/docs-latest-blue?logo=rust' && \
		curl -o 'target/doc/repo-badge.svg' 'https://img.shields.io/badge/github-dusk-blindbidproof-brightgreen?logo=github' && \
		ghp-import -n target/doc && \
		git push -f https://github.com/dusk-network/dusk-blindbidproof gh-pages
help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
