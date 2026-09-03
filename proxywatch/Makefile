OUT_DIR ?= build
GOOS ?= windows
GOARCH ?= amd64
GOCACHE ?= $(abspath $(OUT_DIR)/.go-cache)
TARGETS ?= windows/amd64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
LDFLAGS :=
STRAY_BINARIES := proxywatch proxywatch.exe proxywatch-windows.exe proxywatch-linux-amd64 proxywatch-windows-amd64.exe pwa-linux-amd64 pwa-windows-amd64.exe

PROXYWATCH_OUT := $(OUT_DIR)/proxywatch-windows-amd64.exe

.PHONY: all build clean check-stray clean-stray

all: build

build: check-stray
	mkdir -p $(OUT_DIR)
	@for t in $(TARGETS); do \
		goos=$${t%/*}; goarch=$${t#*/}; \
		ext=""; suffix="-$${goos}-$${goarch}"; \
		if [ "$$goos" = "windows" ]; then ext=".exe"; fi; \
		printf "Building $$goos/$$goarch...\n"; \
		GOCACHE=$(GOCACHE) GOOS=$$goos GOARCH=$$goarch go build -ldflags '$(LDFLAGS)' -o $(OUT_DIR)/proxywatch$${suffix}$${ext} ./cmd/proxywatch || exit $$?; \
	done

clean:
	rm -rf $(OUT_DIR)

check-stray:
	@bad=0; \
	for f in $(STRAY_BINARIES); do \
		if [ -e "$$f" ]; then \
			printf "error: build artifact outside %s: %s\n" "$(OUT_DIR)" "$$f"; \
			bad=1; \
		fi; \
	done; \
	if [ "$$bad" -ne 0 ]; then \
		printf "use 'make clean-stray' or move artifacts into %s/\n" "$(OUT_DIR)"; \
		exit 1; \
	fi

clean-stray:
	rm -f $(STRAY_BINARIES)
