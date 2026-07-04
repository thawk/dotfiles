#!/usr/bin/env bash

my_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATH=${PATH/:${my_DIR}\/bin/}

CMD_PATH=$(type -P "b2" 2>/dev/null)

if [[ -n "$CMD_PATH" && "$CMD_PATH" != "$my_DIR/bin/b2" ]]; then
  # use exists b2 command
  false
else
  [[ -d "$HOME/workspace" ]] && [[ -n "$(find "$HOME/workspace" -maxdepth 1 -type d -name boost -o -name "boost_*")" ]]
fi
