#!/usr/bin/env bash

convert() {
    sed -E '
s/^[[:space:]]*!/#/;
s/^[[:space:]]*\*\.?([[:alnum:]]+)[[:space:]]*:[[:space:]]*(#[[:xdigit:]]+).*/\1="\2"/
    '
}

if [[ -n "$1" ]]; then
    convert < "$1"
else
    convert
fi
