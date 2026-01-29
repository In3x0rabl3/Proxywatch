OUT_DIR ?= dist
GOOS ?= windows
GOARCH ?= amd64
SRC_DIR ?= proxywatch

.PHONY: all build clean

all: build

build:
	$(MAKE) -C $(SRC_DIR) build OUT_DIR=$(OUT_DIR) GOOS=$(GOOS) GOARCH=$(GOARCH)

clean:
	$(MAKE) -C $(SRC_DIR) clean OUT_DIR=$(OUT_DIR)
