.DEFAULT_GOAL := help

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
BIN_NAME := boltwarden
BIN_PATH := $(BINDIR)/$(BIN_NAME)
CARGO ?= cargo
NPM ?= npm
BROWSER_TARGET ?= all

.PHONY: help all build release install install-browser uninstall check test clean extension-deps extension-check extension-test extension-build extension-zip extension-release-check playground security package package-macos packaging-test

##@ General
help: ## Show available targets (default)
	@awk 'BEGIN { \
		FS = ":.*## "; \
		if (!ENVIRON["NO_COLOR"]) { \
			cyan = "\033[1;36m"; blue = "\033[1;34m"; \
			bold = "\033[1m"; reset = "\033[0m"; \
		} \
		printf "\n%s", cyan; \
		print "  BBBB   OOO  L     TTTTT W   W  AAA  RRRR  DDDD  EEEEE N   N"; \
		print "  B   B O   O L       T   W   W A   A R   R D   D E     NN  N"; \
		printf "%s", blue; \
		print "  BBBB  O   O L       T   W W W AAAAA RRRR  D   D EEE   N N N"; \
		print "  B   B O   O L       T   WW WW A   A R  R  D   D E     N  NN"; \
		print "  BBBB   OOO  LLLLL   T   W   W A   A R   R DDDD  EEEEE N   N"; \
		printf "%s\n  %sUsage:%s make [target]\n", reset, bold, reset; \
	} \
	/^##@ / { printf "\n  %s%s%s\n", bold, substr($$0, 5), reset } \
	/^[a-zA-Z0-9_-]+:.*## / { printf "    %s%-24s%s %s\n", cyan, $$1, reset, $$2 } \
	END { printf "\n  Disable colors: NO_COLOR=1 make help\n\n" }' $(MAKEFILE_LIST)

##@ Rust build and checks
all: release ## Build the release binary

build: ## Build the debug binary
	$(CARGO) build

release: ## Build the release binary
	python3 scripts/third-party-notices.py rust THIRD_PARTY_NOTICES.txt
	$(CARGO) build --release

check: ## Check Rust code
	$(CARGO) check

test: ## Run Rust tests
	$(CARGO) test --locked -- --test-threads=1

clean: ## Remove Rust build artifacts
	$(CARGO) clean

##@ Installation
install: ## Install the existing release binary
	sh scripts/install.sh install-binary "target/release/$(BIN_NAME)" "$(DESTDIR)$(BIN_PATH)"

install-browser: ## Register the installed binary with browsers (BROWSER_TARGET=all)
	"$(BIN_PATH)" install-browser --browser "$(BROWSER_TARGET)" --path "$(BIN_PATH)"

uninstall: ## Remove the installed binary
	sh scripts/install.sh uninstall-binary "$(DESTDIR)$(BIN_PATH)"

##@ Browser extension
extension-deps: ## Install browser extension dependencies
	$(NPM) --prefix extension ci

extension-check: ## Typecheck the browser extension
	$(NPM) --prefix extension run typecheck

extension-test: ## Run browser extension tests
	$(NPM) --prefix extension test

extension-build: ## Build the browser extension
	$(NPM) --prefix extension run build

extension-zip: ## Package the browser extension
	python3 scripts/third-party-notices.py npm extension/public/THIRD_PARTY_NOTICES.txt
	$(NPM) --prefix extension run zip

extension-release-check: ## Validate built store manifests and ZIPs
	$(NPM) --prefix extension run check:release

playground: ## Start the extension playground
	$(NPM) --prefix extension run playground

##@ Release and security
security: ## Audit Rust and npm dependencies (requires cargo-audit)
	@$(CARGO) audit --version >/dev/null 2>&1 || { echo 'Install audit tooling first: cargo install cargo-audit --version 0.22.2 --locked' >&2; exit 1; }
	$(CARGO) audit --deny warnings
	$(NPM) --prefix extension audit

package: ## Build tested Linux tar, Debian, Arch, and RPM packages with Docker
	docker buildx build -f packaging/Dockerfile --output type=local,dest=dist .

package-macos: ## Build a universal, ad-hoc signed Boltwarden.app ZIP (on macOS)
	python3 scripts/third-party-notices.py rust THIRD_PARTY_NOTICES.txt
	$(CARGO) build --locked --release --target aarch64-apple-darwin --bins
	$(CARGO) build --locked --release --target x86_64-apple-darwin --bins
	rm -rf target/Boltwarden.iconset
	$(CARGO) run --locked --example macos_icon -- target/Boltwarden.iconset
	python3 scripts/package-macos.py --iconset target/Boltwarden.iconset --output dist \
		--binary-dir target/aarch64-apple-darwin/release --binary-dir target/x86_64-apple-darwin/release

packaging-test: ## Check packaging and setup opt-in behavior
	python3 -m unittest discover -s scripts/tests
