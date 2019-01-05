#!/usr/bin/env bash

# use peco if exists
! (type peco &> /dev/null) && ((type python2 &> /dev/null) || (type python2.7 &> /dev/null))
