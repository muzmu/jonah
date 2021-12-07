#!/bin/bash

set -ex

PARENT_DIR=$(basename "${PWD%/*}")
CURRENT_DIR="${PWD##*/}"
IMAGE_NAME="$PARENT_DIR/$CURRENT_DIR"
TAG="${1}"

REGISTRY="localhost:5000"

sudo docker build -t ${REGISTRY}/${IMAGE_NAME}:${TAG} .
sudo cp /jonah/jonah.log jonah.log
sudo oras push ${REGISTRY}/${IMAGE_NAME}:${TAG} --manifest-config /dev/null:application/vnd.oci.jonah.config jonah.log:text/plain
