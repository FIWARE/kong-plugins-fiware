#!/usr/bin/env bash

##
## Runs all tests using pongo
##

# Build pongo test image
./pongo/build.sh

# Run tests for: ngsi-ishare-policies
PONGO_PLUGIN_SOURCE=./kong-plugin-ngsi-ishare-policies ./pongo/pongo-docker.sh run

# Run tests for: auth-endpoint-config-ishare
PONGO_PLUGIN_SOURCE=./kong-plugin-auth-endpoint-config-ishare ./pongo/pongo-docker.sh run
