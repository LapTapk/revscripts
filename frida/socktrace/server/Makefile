SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c

# -------- project knobs --------
TARGET      ?= x86_64-unknown-linux-musl
PROFILE     ?= release
CARGO       ?= cargo

# If you have a single-bin project, this auto-detects the first bin name.
# You can override: make BIN=mybin
BIN ?= $(shell $(CARGO) metadata --no-deps --format-version 1 2>/dev/null \
	| sed -n 's/.*"targets":\[\{"kind":\["bin"\],"name":"\([^"]*\)".*/\1/p' \
	| head -n 1)

# Install prefix
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

# Static-friendly flags
# -C target-feature=+crt-static generally redundant for musl target, but harmless.
RUSTFLAGS ?= -C target-feature=+crt-static
CARGOFLAGS ?=
JOBS ?=

# -------- derived --------
ifneq ($(PROFILE),release)
  PROFILE_DIR := debug
  CARGO_PROFILE_FLAG :=
else
  PROFILE_DIR := release
  CARGO_PROFILE_FLAG := --release
endif

OUT_DIR := target/$(TARGET)/$(PROFILE_DIR)
BIN_PATH := $(OUT_DIR)/$(BIN)

# -------- targets --------
.PHONY: all release debug build run test fmt clippy clean strip install info check-target

all: release

check-target:
	@rustup target list --installed | grep -qx "$(TARGET)" || { \
	  echo "Missing Rust target $(TARGET). Install with:"; \
	  echo "  rustup target add $(TARGET)"; \
	  exit 1; \
	}

info:
	@echo "TARGET=$(TARGET)"
	@echo "PROFILE=$(PROFILE)"
	@echo "BIN=$(BIN)"
	@echo "BIN_PATH=$(BIN_PATH)"

release: PROFILE=release
release: build

debug: PROFILE=debug
debug: build

build: check-target
	@echo "Building $(BIN) for $(TARGET) ($(PROFILE)) [static musl]"
	@RUSTFLAGS="$(RUSTFLAGS)" \
	$(CARGO) build $(CARGO_PROFILE_FLAG) --target "$(TARGET)" $(CARGOFLAGS) $(JOBS)

run: PROFILE=debug
run: build
	@echo "Running: $(BIN_PATH)"
	@"$(BIN_PATH)" || true

test: check-target
	@RUSTFLAGS="$(RUSTFLAGS)" \
	$(CARGO) test --target "$(TARGET)" $(CARGOFLAGS) $(JOBS)

fmt:
	@$(CARGO) fmt

clippy: check-target
	@RUSTFLAGS="$(RUSTFLAGS)" \
	$(CARGO) clippy --target "$(TARGET)" $(CARGO_PROFILE_FLAG) -- -D warnings

strip: release
	@command -v strip >/dev/null 2>&1 || { echo "strip not found (binutils)"; exit 1; }
	@echo "Stripping: $(BIN_PATH)"
	@strip -s "$(BIN_PATH)"

install: release
	@test -n "$(BIN)" || { echo "BIN could not be detected. Use: make install BIN=yourbin"; exit 1; }
	@install -d "$(BINDIR)"
	@install -m 0755 "$(BIN_PATH)" "$(BINDIR)/$(BIN)"
	@echo "Installed to: $(BINDIR)/$(BIN)"

clean:
	@$(CARGO) clean
