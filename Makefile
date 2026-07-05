# Vev — build, test, and packaging. The Makefile handles everything; there are
# no build/clean shell scripts to run by hand.
#
# CEF requires the assembled app bundle to spawn its helper processes, so a
# bare `cargo run` cannot launch the browser — always go through `make run` /
# `make bundle`. macOS is the verified build today; the same Rust workspace and
# CEF back the Windows and Linux targets.

SHELL       := /bin/bash
CEF_PATH    ?= $(HOME)/.local/share/cef
BUNDLE_DIR  := target/bundle
APP         := $(BUNDLE_DIR)/vev.app
BUNDLE_ID   := com.vev.browser
# bundle-cef-app reads CEF_PATH; the loader needs the framework on the dyld
# path. Both must be exported into every recipe's environment.
export CEF_PATH
export DYLD_FALLBACK_LIBRARY_PATH := :$(CEF_PATH):$(CEF_PATH)/Chromium Embedded Framework.framework/Libraries

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test: ## Run the full workspace test suite
	cargo test --workspace --exclude vev

.PHONY: check
check: ## Type-check everything without running
	cargo check --workspace

.PHONY: fmt
fmt: ## Format the Rust workspace
	cargo fmt --all

.PHONY: bundle
bundle: ## Build + assemble the macOS .app bundle (no launch)
	@command -v bundle-cef-app >/dev/null || { echo "bundle-cef-app not found; install it from a cef-rs checkout"; exit 1; }
	@[ -d "$(CEF_PATH)" ] || { echo "CEF distribution not found at CEF_PATH=$(CEF_PATH). Set CEF_PATH or run: export-cef-dir $(CEF_PATH)"; exit 1; }
	cd src-tauri && bundle-cef-app vev -o ../$(BUNDLE_DIR) -d Vev -i $(BUNDLE_ID)

.PHONY: run
run: bundle ## Build, bundle, and launch Vev
	open $(APP)

.PHONY: autotest
autotest: bundle ## Launch the in-app runtime self-test suite
	$(APP)/Contents/MacOS/vev --vev-autotest

.PHONY: train
train: ## Retrain the Huma phishing model and export ONNX
	python3 scripts/train_guard/gen_dataset.py > /tmp/vev_urls.tsv
	cargo run -q --example dump_features -p huma < /tmp/vev_urls.tsv > /tmp/vev_features.csv
	python3 scripts/train_guard/train.py /tmp/vev_features.csv crates/huma/src/model.onnx

.PHONY: clean
clean: ## Kill stale processes and clear bundle / LaunchServices state
	-pkill -9 -f "$(APP)" 2>/dev/null || true
	-pkill -9 -x vev 2>/dev/null || true
	-pkill -9 -x vev_helper 2>/dev/null || true
	@[ -d "$(APP)" ] && xattr -cr "$(APP)" 2>/dev/null || true
	-/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u "$(APP)" 2>/dev/null || true
	rm -rf "$(BUNDLE_DIR)"
	@echo "clean: killed processes and removed $(BUNDLE_DIR). Rebuild with 'make run'."

.PHONY: verify
verify: ## Run the CDP privacy verification (needs a running build)
	node scripts/verify-fingerprint.mjs
	node scripts/verify-network.mjs

# ---- Cross-platform packaging (same workspace + CEF per platform) ----
# The Windows/Linux flavors of bundle-cef-app take no -d/-i flags (flat
# directory layout, no app bundle); they build the binary themselves.
.PHONY: dist-win
dist-win: ## Package for Windows (run on Windows with the Windows CEF distribution)
	cd src-tauri && bundle-cef-app vev -o ../$(BUNDLE_DIR) --release

.PHONY: dist-linux
dist-linux: ## Package for Linux (run on Linux with the Linux CEF distribution)
	cd src-tauri && bundle-cef-app vev -o ../$(BUNDLE_DIR) --release

# ---- Website ----
.PHONY: web
web: ## Run the website dev server (Astro)
	cd website && npm run dev

.PHONY: web-build
web-build: ## Build the website for production
	cd website && npm run build
