# Every app uses these targets; change only BINARY and PLATFORMS.
BINARY := starter
# Release platforms as os/arch.
PLATFORMS := linux/amd64

# Local settings for make dev.
-include .env
export

.PHONY: dev build test frontend release preview

frontend/node_modules: frontend/bun.lock
	cd frontend && bun install --frozen-lockfile
	@touch $@

frontend: frontend/node_modules
	cd frontend && bun --bun run build

# The binary is built before the watcher starts, because Vite empties dist on each rebuild.
# Vite then rebuilds frontend/dist on save and the app serves it from disk; refresh to see changes.
dev: frontend
	go build -o bin/$(BINARY) .
	@(cd frontend && exec bun node_modules/.bin/vite build --watch --logLevel warn) & watcher=$$!; \
	trap 'kill $$watcher 2>/dev/null' EXIT; \
	APP_ENV=development bin/$(BINARY)

build: frontend
	go build -o bin/$(BINARY) .

test: frontend
	cd frontend && bun x biome check
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './frontend/*')); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go test -race ./...

# The app in a browser with a fake Rauthy; preview_test.go prints a cookie per group.
preview: frontend
	go test -tags preview -run TestPreview -timeout 0 -v .

# One binary per platform and checksums for a GitHub release; release.yml runs this on a tag.
# Go stamps the tag only into a build from a clean checkout at that tag, and
# update verifies that stamp, so anything else is refused here.
release: frontend
	rm -rf dist && mkdir -p dist
	for platform in $(PLATFORMS); do CGO_ENABLED=0 GOOS=$${platform%/*} GOARCH=$${platform#*/} go build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-$${platform%/*}-$${platform#*/} . || exit 1; done
	@version=$$(go version -m dist/$(BINARY)-$(subst /,-,$(firstword $(PLATFORMS))) | awk '$$1 == "mod" { print $$3 }'); \
	echo "$$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "built $$version, not a clean checkout of a version tag"; exit 1; }
	cd dist && shasum -a 256 $(BINARY)-* > checksums.txt
