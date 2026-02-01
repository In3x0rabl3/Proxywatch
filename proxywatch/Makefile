OUT_DIR ?= dist
GOOS ?= windows
GOARCH ?= amd64
GOCACHE ?= $(abspath $(OUT_DIR)/.go-cache)
GEN_TLS_GOOS ?= $(shell go env GOOS)
GEN_TLS_GOARCH ?= $(shell go env GOARCH)

PROXYWATCH_OUT := $(OUT_DIR)/proxywatch.exe
AGENT_OUT := $(OUT_DIR)/pwa.exe
GEN_TLS_OUT := internal/agent/generated_tls.go

.PHONY: all build clean gen-tls

all: build

build: gen-tls
	mkdir -p $(OUT_DIR)
	GOCACHE=$(GOCACHE) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(PROXYWATCH_OUT) ./cmd/proxywatch
	GOCACHE=$(GOCACHE) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(AGENT_OUT) ./cmd/proxywatch-agent

gen-tls:
	GOCACHE=$(GOCACHE) GOOS=$(GEN_TLS_GOOS) GOARCH=$(GEN_TLS_GOARCH) go run ./scripts/gen_tls.go

clean:
	rm -rf $(OUT_DIR)
	rm -f $(GEN_TLS_OUT)
