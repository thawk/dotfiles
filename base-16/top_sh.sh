# 为base16生成必要的信息
BASE16_SHELL=$HOME/.vim/bundle/base16-shell
[ -n "$PS1" ] && [ -s "$BASE16_SHELL/profile_helper.sh" ] && eval "$("$BASE16_SHELL/profile_helper.sh")"

if [[ "$DOTFILES_THEME" == "base16" ]]
then
    # 在顶层SHELL中恢复base16的配色
    # shellcheck disable=SC1091
    [ "$SHLVL" -eq 1 ] && [ -e "$HOME/.base16_theme" ] && source "$HOME/.base16_theme"
fi
