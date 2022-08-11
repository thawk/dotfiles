export DYNAMIC_COLORS_ROOT="${XDG_CACHE_HOME:-${HOME}/.cache}/dynamic-colors"

if [[ -z "$DOTFILES_THEME" ]] || [[ "$DOTFILES_THEME" == "solarized" ]]
then
    # 在顶层SHELL中恢复终端配色 
    [ "$SHLVL" -eq 1 ] &&  "${DOTFILES_ROOT}"/dynamic-colors/bin/dynamic-colors init
fi
