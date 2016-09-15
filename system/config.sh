# Disable flow control
stty -ixon

export HISTIGNORE='&:ls:ll:[bf]g:exit'
# ignore line begin with spaces
export HISTIGNORE='$HISTIGNORE:[ 	]*'
export HISTCONTROL=erasedups:ignorespace

