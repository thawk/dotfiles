#!/usr/bin/env bash

my_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PATH=$(echo $PATH | sed -e "s;:${my_DIR}/bin;;")

if type b2 &> /dev/null
then
    # use exists b2 command
    false
else
    [[ -d "$HOME/workspace" ]] && [[ -n "$(find $HOME/workspace -maxdepth 1 -type d -name "boost_*" &> /dev/null)" ]]
fi

