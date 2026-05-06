.PHONY: build build-dashboard build-go generate test-keys dev lint test install uninstall release-local clean dev-install update-policies preflight preflight-node ci install-hooks

GO_MIN_VERSION := 1.25
NODE_MIN_VERSION := 26

## preflight: verify toolchain versions and environment before building
preflight:
	@if [ "$$(id -u)" = "0" ] && [ "$$BOUNDARYLAB_ALLOW_ROOT" != "1" ]; then \
	  echo "ERROR: Do not run 'make install' as root. It installs to ~/.boundarylab/ (your user dir)."; \
	  echo "       If you really mean it, set BOUNDARYLAB_ALLOW_ROOT=1"; exit 1; \
	fi
	@go_ver=$$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//'); \
	 if [ -z "$$go_ver" ]; then \
	   echo "ERROR: Go not found. Install Go >= $(GO_MIN_VERSION): https://go.dev/dl/"; exit 1; \
	 fi; \
	 major=$$(echo $$go_ver | cut -d. -f1); minor=$$(echo $$go_ver | cut -d. -f2); \
	 req_major=$$(echo $(GO_MIN_VERSION) | cut -d. -f1); req_minor=$$(echo $(GO_MIN_VERSION) | cut -d. -f2); \
	 if [ "$$major" -lt "$$req_major" ] || { [ "$$major" -eq "$$req_major" ] && [ "$$minor" -lt "$$req_minor" ]; }; then \
	   echo "ERROR: Go >= $(GO_MIN_VERSION) required (found $$go_ver). Install: https://go.dev/dl/"; exit 1; \
	 fi

## preflight-node: verify Node version (only for dashboard targets)
preflight-node:
	@node_ver=$$(node --version 2>/dev/null | sed 's/v//' | cut -d. -f1); \
	 if [ -z "$$node_ver" ]; then \
	   echo "ERROR: Node.js not found. Install Node >= $(NODE_MIN_VERSION): nvm install $(NODE_MIN_VERSION)"; exit 1; \
	 fi; \
	 if [ "$$node_ver" -lt "$(NODE_MIN_VERSION)" ]; then \
	   echo "ERROR: Node >= $(NODE_MIN_VERSION) required (found v$$(node --version)). Run: nvm install $(NODE_MIN_VERSION)"; exit 1; \
	 fi

## build-dashboard: compile the React dashboard into dashboard/dist/ (required for go:embed)
build-dashboard:
	@echo "==> Building dashboard..."
	@cd dashboard && \
	  (test -d node_modules || npm ci) && \
	  npm run build

## build-go: compile Go binaries only — use when dashboard/dist/ already exists
build-go: preflight
	go build -o bin/ ./cmd/...

## build: compile all Go binaries into bin/
build: preflight build-dashboard
	go build -o bin/ ./cmd/...

## clean: remove build artifacts and stale binaries
clean:
	rm -rf bin/

## generate: export policies.json for the dashboard static fallback (no daemon needed)
generate:
	go run ./cmd/boundarylab/ policy export --dir ./policies --out ./dashboard/public/policies.json

## test-keys: generate Ed25519 test key pair for go test ./... (keys are gitignored, run once)
test-keys:
	@mkdir -p testdata
	openssl genpkey -algorithm ed25519 -out testdata/bundle_signing_key.pem
	openssl pkey -in testdata/bundle_signing_key.pem -pubout -out testdata/bundle_signing_pub.pem
	@echo "Test keys written to testdata/"

## lint: run golangci-lint on all Go packages
lint:
	golangci-lint run ./...

## test: run all Go tests (requires testdata/ keys — run make test-keys first)
test:
	go test ./... -race -count=1

## dev: start daemon + dashboard dev server (builds dashboard first if dist/ missing)
dev: preflight preflight-node
	@test -d dashboard/dist || $(MAKE) build-dashboard
	@echo "Starting daemon on :9090..."
	@go build -o /tmp/boundarylab-daemon ./cmd/boundarylab-daemon/ && \
	  /tmp/boundarylab-daemon -policy-dir ./policies &
	@echo "Starting dashboard dev server on :5173..."
	@cd dashboard && npm run dev

## install: one-command build + deploy + restart (idempotent)
install: build
	@echo "==> Stopping existing daemon (if running)..."
	@(launchctl bootout gui/$$(id -u)/com.boundarylab.daemon 2>/dev/null || \
	  systemctl --user stop boundarylab-daemon 2>/dev/null || true) && sleep 1
	@echo "==> Deploying binaries..."
	@mkdir -p ~/.boundarylab
	@rm -f ~/.boundarylab/boundarylab ~/.boundarylab/boundarylab-hook ~/.boundarylab/boundarylab-daemon
	@cp bin/boundarylab bin/boundarylab-hook bin/boundarylab-daemon ~/.boundarylab/
	@chmod +x ~/.boundarylab/boundarylab ~/.boundarylab/boundarylab-hook ~/.boundarylab/boundarylab-daemon
	@echo "==> Running setup (policies + service + hook)..."
	@~/.boundarylab/boundarylab setup --yes --skip-binaries --policy-dir ./policies

## dev-install: full fresh setup (test-keys + dashboard deps + build + install)
dev-install: preflight preflight-node
	@echo "==> Full development setup..."
	@test -f testdata/bundle_signing_key.pem || $(MAKE) test-keys
	@cd dashboard && npm install
	@$(MAKE) install

## update-policies: refresh policies without rebuilding binaries
update-policies:
	@echo "==> Syncing policies to ~/.boundarylab/policies/..."
	@mkdir -p ~/.boundarylab/policies
	@rsync -a --delete ./policies/ ~/.boundarylab/policies/
	@sleep 0.2
	@~/.boundarylab/boundarylab reload 2>/dev/null || echo "Daemon not running; policies synced to disk."

## uninstall: completely remove boundarylab
uninstall:
	@~/.boundarylab/boundarylab uninstall --yes 2>/dev/null || \
	  (echo "BoundaryLab binary not found or hung. Manual cleanup:" && \
	   echo "  pgrep -f boundarylab-daemon | xargs kill -9 2>/dev/null" && \
	   echo "  rm -f ~/Library/LaunchAgents/com.boundarylab.daemon.plist" && \
	   echo "  rm -rf ~/.boundarylab && rm -f /tmp/boundarylab.sock" && \
	   echo "  Remove '# BoundaryLab' block from your shell rc file")

## release-local: build release artifacts locally (for testing)
release-local:
	goreleaser release --snapshot --clean

## ci: run the same checks as GitHub CI (backend + dashboard)
ci: preflight preflight-node
	@echo "==> Backend: build"
	@go build ./...
	@echo "==> Backend: test"
	@go test -race -timeout 120s ./...
	@echo "==> Backend: lint"
	@golangci-lint run ./...
	@echo "==> Dashboard: type-check + test + build"
	@cd dashboard && npm ci && npm run type-check && npm run test && npm run build
	@echo ""
	@echo "✓ All CI checks passed."

## install-hooks: install git pre-push hook to run CI before every push
install-hooks:
	@echo "==> Installing git pre-push hook..."
	@cp scripts/pre-push .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "  ✓ Pre-push hook installed. 'make ci' will run before every push."
