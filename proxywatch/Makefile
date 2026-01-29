OUT_DIR ?= dist
GOOS ?= windows
GOARCH ?= amd64

PROXYWATCH_OUT := $(OUT_DIR)/proxywatch.exe
AGENT_OUT := $(OUT_DIR)/beaconhunter-agent.exe

.PHONY: all build clean

all: build

build:
	mkdir -p $(OUT_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(PROXYWATCH_OUT) ./cmd/proxywatch
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(AGENT_OUT) ./cmd/beaconhunter-agent

clean:
	rm -rf $(OUT_DIR)
