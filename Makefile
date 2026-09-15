.PHONY: build test dist
build:
	go build -trimpath -o dist/subexposure ./cmd/subexposure
test:
	go test ./...
	go vet ./...
dist:
	mkdir -p dist
	@for os in windows linux darwin; do \
	  for arch in amd64 arm64; do \
	    ext=""; [ "$$os" != windows ] || ext=".exe"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="-s -w" -o dist/subexposure-$$os-$$arch$$ext ./cmd/subexposure || exit 1; \
	  done; \
	done
