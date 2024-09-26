#!/bin/bash
nitro-cli build-enclave --docker-uri nitronotary:latest --docker-dir /enclave --output-file notary.eif --private-key ca-private.pem --signing-certificate ca.crt

nitro-cli describe-eif --eif-path notary.eif
nitro-cli run-enclave --cpu-count 2 --memory 256 --eif-path notary.eif
