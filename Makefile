BINARY  := cra-doc-kit
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/moveeeax/cra-doc-kit/internal/cli.Version=$(VERSION)

.PHONY: help build test lint fmt examples clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-10s %s\n", $$1, $$2}'

build: ## Build ./bin/cra-doc-kit
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

test: ## Run the test suite with the race detector
	go test -race ./...

lint: ## gofmt and go vet
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt found unformatted files"; exit 1)
	go vet ./...

fmt: ## Format the tree
	gofmt -w .

examples: build ## Regenerate the example deliverables under out/
	./bin/$(BINARY) vex \
		--scan examples/scan.grype.json \
		--triage examples/triage.yaml \
		--profile examples/product.yaml \
		--kev examples/kev.json \
		--out out/vex.json
	./bin/$(BINARY) gapcheck \
		--sbom examples/sbom.cdx.json \
		--scan examples/scan.grype.json \
		--vex out/vex.json \
		--kev examples/kev.json \
		--fail-on none \
		--out out/gap-check.md
	./bin/$(BINARY) annex \
		--sbom examples/sbom.cdx.json \
		--profile examples/product.yaml \
		--scan examples/scan.grype.json \
		--vex out/vex.json \
		--kev examples/kev.json \
		--out out/annex-vii.md

clean: ## Remove build output
	rm -rf bin out
