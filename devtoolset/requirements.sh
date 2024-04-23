#!/usr/bin/env bash
# Time: 2023-08-08 09:30:14

ls /opt/rh 2> /dev/null | grep "^devtoolset-\|^llvm-toolset\|^rh-nodejs" >& /dev/null
