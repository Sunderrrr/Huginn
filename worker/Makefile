BINARY := huginn-worker
PKG := github.com/Sunderrrr/Huginn/worker
VERSION ?= dev
LDFLAGS := -s -w -X $(PKG)/internal/config.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64

.PHONY: build test vet lint clean release

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/huginn-worker

test:
	go test -race -cover ./...

vet:
	go vet ./...

lint:
	golangci-lint run

clean:
	rm -rf bin dist

# Cross-compiled, reproducible static binaries for each platform.
release: clean
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/$(BINARY)-$$os-$$arch ./cmd/huginn-worker; \
	done
	@ls -l dist
