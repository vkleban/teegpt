.PHONY: all

all:
	@echo "Please specify a target"
	
build:
	docker build -t tlsnotary-nitro:latest .

build-enclave-debug: build
	mkdir -p build
	nitro-cli build-enclave --docker-uri tlsnotary-nitro:latest --output-file build/tlsnotary-debug.eif
	nitro-cli run-enclave --config nitro-config-debug.json

build-enclave-prod: build
	mkdir -p build
	nitro-cli build-enclave --docker-uri tlsnotary-nitro:latest --output-file build/tlsnotary-prod.eif
	nitro-cli run-enclave --config nitro-config-prod.json

terminate:
	nitro-cli terminate-enclave --all