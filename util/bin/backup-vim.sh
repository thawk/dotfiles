#!/bin/sh

DEST_FILE=${1:-dotvim.tar.bz2}

tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .git --exclude "*.so" .vim
