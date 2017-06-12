export DYNAMIC_COLORS_ROOT="${DOTFILES_ROOT}/solarized/dynamic-colors"

if [[ "$DOTFILES_THEME" == "solarized" ]]
then
    echo "reset dynamic-colors to solarized" >> /tmp/dotfiles.log 
    # 在顶层SHELL中恢复终端配色 
    [ "$SHLVL" -eq 1 ] &&  dynamic-colors init
fi
