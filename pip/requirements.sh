#!/usr/bin/env bash

#type pip &> /dev/null
if [[ type python &> /dev/null ]]
then
  python python -m pip &> /dev/null || python3 -m pip &> /dev/null
else
  false
fi
