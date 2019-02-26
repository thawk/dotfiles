# PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
# PS1='\u@\h:\w\$ '

#fg_black=$(tput setaf 0)
#fg_red=$(tput setaf 1)
#fg_green=$(tput setaf 2)
#fg_yellow=$(tput setaf 3)
#fg_blue=$(tput setaf 4)
#fg_magenta=$(tput setaf 5)
#fg_cyan=$(tput setaf 6)
#fg_white=$(tput setaf 7)
#fg_default=$(tput setaf 9)

#bg_black=$(tput setab 0)
#bg_red=$(tput setab 1)
#bg_green=$(tput setab 2)
#bg_yellow=$(tput setab 3)
#bg_blue=$(tput setab 4)
#bg_magenta=$(tput setab 5)
#bg_cyan=$(tput setab 6)
#bg_white=$(tput setab 7)
#bg_default=$(tput setab 9)

#reset=$(tput sgr0)
#bright=$(tput bold)
#dim=$(tput dim)
#standout=$(tput smso)
#underscore=$(tput smul)
#not_underscore=$(tput rmul)
#blink=$(tput blink)
#reverse=$(tput rev)
#hidden=$(tput invis)

#PS1="\[$(tput sgr0)\]\[$(tput setab 0)\] \u@\h \[$(tput setaf 0)\]\[$(tput setab 4)\] \w \[$(tput sgr0)\]\[$(tput setaf 4)\]\[$(tput sgr0)\] "
PS1="\[$(tput sgr0)\]\[$(tput setab 0)\] \u@\h \[$(tput setaf 0)\]\[$(tput setab 4)\] \w \[$(tput sgr0)\]\[$(tput setaf 4)\]${X_SCLS:+\[$(tput setab 2)\]\[$(tput setaf 0)\] ${X_SCLS}\[$(tput sgr0)\]\[$(tput setaf 2)\]}\[$(tput sgr0)\] "
