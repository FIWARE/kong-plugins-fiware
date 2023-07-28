#!/usr/bin/env bash

# Any parameters passed to this script will be passed to Pongo inside
# the container.
#
# var PONGO_PLUGIN_SOURCE should point to the directory where
# the plugin source is located (top-level of repo). Defaults
# to the current directory.
#
# set var PONGO_VERSION for the version of Pongo to use,
# defaults to 'master' for the master branch.

function main {

  PONGO_VERSION_DEFAULT="2.7.0"
  IMAGE_NAME_DEFAULT="pongo"  
  KONG_VERSION_DEFAULT="2.8.1"
  #KONG_IMAGE_DEFAULT="kong/kong-alpine"
  
  # get plugin source location, default to PWD
  if [[ -z $PONGO_PLUGIN_SOURCE ]]; then
    PONGO_PLUGIN_SOURCE=.
  fi
  PONGO_PLUGIN_SOURCE=$(realpath "$PONGO_PLUGIN_SOURCE")

  if [[ -z $PONGO_VERSION ]]; then
    PONGO_VERSION=$PONGO_VERSION_DEFAULT
  fi

  if [[ -z $IMAGE_NAME ]]; then
    IMAGE_NAME=$IMAGE_NAME_DEFAULT
  fi

  if [[ -z $KONG_VERSION ]]; then
    KONG_VERSION=$KONG_VERSION_DEFAULT
  fi

  if [[ -z $KONG_IMAGE ]]; then
    KONG_IMAGE=$KONG_IMAGE_DEFAULT
  fi

  # run the command
  docker run -t --rm \
    -v "/var/run/docker.sock:/var/run/docker.sock" \
    -v "$PONGO_PLUGIN_SOURCE:/pongo_wd" \
    -e "KONG_VERSION=$KONG_VERSION" \
    -e "KONG_IMAGE=$KONG_IMAGE" \
    --cidfile "$PONGO_PLUGIN_SOURCE/.containerid" \
    "$IMAGE_NAME:$PONGO_VERSION" "$@"

  local result=$?

  rm "$PONGO_PLUGIN_SOURCE/.containerid"

  exit $result
}

main "$@"
