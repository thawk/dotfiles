type wine &> /dev/null && alias wine='env LANG=zh_CN.UTF-8 wine'
type xprop &> /dev/null && alias xpop='xprop | grep --color=none "WM_CLASS\|^WM_NAME" | xmessage -file -'
type tmux &> /dev/null && alias tmux='tmux -2'

