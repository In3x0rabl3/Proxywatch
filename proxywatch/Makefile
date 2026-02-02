OUT_DIR ?= build
GOOS ?= windows
GOARCH ?= amd64
GOCACHE ?= $(abspath $(OUT_DIR)/.go-cache)
GEN_TLS_GOOS ?= $(shell go env GOOS)
GEN_TLS_GOARCH ?= $(shell go env GOARCH)
TARGETS ?= windows/amd64 linux/amd64
LDFLAGS :=

ifneq ($(strip $(BLOODHOUND_API_URL)),)
LDFLAGS += -X proxywatch/internal/bloodhound.BloodhoundAPIURL=$(BLOODHOUND_API_URL)
endif
ifneq ($(strip $(BLOODHOUND_API_TOKEN)),)
LDFLAGS += -X proxywatch/internal/bloodhound.BloodhoundAPIToken=$(BLOODHOUND_API_TOKEN)
endif
ifneq ($(strip $(BLOODHOUND_API_TOKEN_ID)),)
LDFLAGS += -X proxywatch/internal/bloodhound.BloodhoundAPITokenID=$(BLOODHOUND_API_TOKEN_ID)
endif

PROXYWATCH_OUT := $(OUT_DIR)/proxywatch.exe
AGENT_OUT := $(OUT_DIR)/pwa.exe
GEN_TLS_OUT := internal/agent/generated_tls.go

.PHONY: all build clean gen-tls

all: build

build: gen-tls
	mkdir -p $(OUT_DIR)
	@for t in $(TARGETS); do \
		goos=$${t%/*}; goarch=$${t#*/}; \
		ext=""; suffix="-$${goos}-$${goarch}"; \
		if [ "$$goos" = "windows" ]; then ext=".exe"; suffix=""; fi; \
		printf "Building $$goos/$$goarch...\n"; \
		GOCACHE=$(GOCACHE) GOOS=$$goos GOARCH=$$goarch go build -ldflags '$(LDFLAGS)' -o $(OUT_DIR)/proxywatch$${suffix}$${ext} ./cmd/proxywatch || exit $$?; \
		GOCACHE=$(GOCACHE) GOOS=$$goos GOARCH=$$goarch go build -ldflags '$(LDFLAGS)' -o $(OUT_DIR)/pwa$${suffix}$${ext} ./cmd/proxywatch-agent || exit $$?; \
	done

gen-tls:
	GOCACHE=$(GOCACHE) GOOS=$(GEN_TLS_GOOS) GOARCH=$(GEN_TLS_GOARCH) go run ./scripts/gen_tls.go

clean:
	rm -rf $(OUT_DIR)
	rm -f $(GEN_TLS_OUT)
