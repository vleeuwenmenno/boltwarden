PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
BIN_NAME := bw-quick-access
BIN_PATH := $(BINDIR)/$(BIN_NAME)
SERVICE_NAME ?= bw-quick-access.service
SYSTEMD_USER_DIR ?= $(HOME)/.config/systemd/user
CARGO ?= cargo

.PHONY: all build release install install-service uninstall uninstall-service check test clean

all: release

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install:
	sh scripts/install.sh install-binary "target/release/$(BIN_NAME)" "$(DESTDIR)$(BIN_PATH)"

install-service:
	sh scripts/install.sh install-service "$(BIN_PATH)" "$(SERVICE_NAME)" "$(SYSTEMD_USER_DIR)"

uninstall:
	sh scripts/install.sh uninstall-binary "$(DESTDIR)$(BIN_PATH)"

uninstall-service:
	sh scripts/install.sh uninstall-service "$(SERVICE_NAME)" "$(SYSTEMD_USER_DIR)"

check:
	$(CARGO) check

test:
	$(CARGO) test

clean:
	$(CARGO) clean
