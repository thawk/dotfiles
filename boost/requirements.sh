#!/bin/sh

if type b2 &> /dev/null
then
    true
else
    [ -d "$HOME/workspace" ] && (find -type d -name "boost_*" &> /dev/null)
fi
