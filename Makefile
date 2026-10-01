PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
BIN_NAME := boltwarden
BIN_PATH := $(BINDIR)/$(BIN_NAME)
SERVICE_NAME ?= boltwarden.service
SYSTEMD_USER_DIR ?= $(HOME)/.config/systemd/user
CARGO ?= cargo
NPM ?= npm
BROWSER_TARGET ?= all

.PHONY: all build release install install-service install-browser uninstall uninstall-service check test clean extension-deps extension-check extension-test extension-build extension-zip

all: release

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install:
	sh scripts/install.sh install-binary "target/release/$(BIN_NAME)" "$(DESTDIR)$(BIN_PATH)"

install-service:
	sh scripts/install.sh install-service "$(BIN_PATH)" "$(SERVICE_NAME)" "$(SYSTEMD_USER_DIR)"

install-browser:
	"$(BIN_PATH)" install-browser --browser "$(BROWSER_TARGET)" --path "$(BIN_PATH)"

uninstall:
	sh scripts/install.sh uninstall-binary "$(DESTDIR)$(BIN_PATH)"

uninstall-service:
	sh scripts/install.sh uninstall-service "$(SERVICE_NAME)" "$(SYSTEMD_USER_DIR)"

check:
	$(CARGO) check

test:
	$(CARGO) test

extension-deps:
	$(NPM) --prefix extension ci

extension-check:
	$(NPM) --prefix extension run typecheck

extension-test:
	$(NPM) --prefix extension test

extension-build:
	$(NPM) --prefix extension run build

extension-zip:
	$(NPM) --prefix extension run zip

clean:
	$(CARGO) clean
