OUT_DIR ?= dist
GOOS ?= windows
GOARCH ?= amd64

PROXYWATCH_OUT := $(OUT_DIR)/proxywatch.exe
AGENT_OUT := $(OUT_DIR)/pwa.exe
GEN_TLS_OUT := internal/beaconhunter/generated_tls.go

.PHONY: all build clean gen-tls

all: build

build: gen-tls
	mkdir -p $(OUT_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(PROXYWATCH_OUT) ./cmd/proxywatch
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(AGENT_OUT) ./cmd/proxywatch-agent

gen-tls:
	go run ./scripts/gen_tls.go

clean:
	rm -rf $(OUT_DIR)
	rm -f $(GEN_TLS_OUT)
