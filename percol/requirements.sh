#!/usr/bin/env bash

# use fzf/peco if exists
! (type fzf &> /dev/null) && ! (type peco &> /dev/null) && (type python &> /dev/null)
