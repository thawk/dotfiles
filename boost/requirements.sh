#!/usr/bin/env bash

my_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PATH=$(echo $PATH | sed -e "s;:${my_DIR}/bin;;")

if type b2 &> /dev/null
then
    true
else
    [ -d "$HOME/workspace" ] && (find -type d -name "boost_*" &> /dev/null)
fi

