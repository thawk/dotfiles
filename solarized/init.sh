if [[ "$DOTFILES_THEME" == "solarized" ]]
then
    # 在顶层SHELL中恢复终端配色 
    [ "$SHLVL" -eq 1 ] &&  dynamic-colors init
fi
