ZPLG_HOME="${ZDOTDIR:-$HOME}/.zplugin"

if ! test -d "$ZPLG_HOME"; then
    echo 'Installing zplugin...'
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/zdharma/zplugin/master/doc/install.sh)"
fi

# load zplugin
source "$ZPLG_HOME/bin/zplugin.zsh"
autoload -Uz _zplugin
(( ${+_comps} )) && _comps[zplugin]=_zplugin

# Tmux
zplugin ice svn if'[[ -n "$commands[tmux]" ]]' lucid
zplugin snippet OMZ::plugins/tmux

# OS specific plugins
if [[ "$OSTYPE" == "darwin"* ]]; then
    # zplugin ice wait"0" lucid atinit"local ZSH=\$PWD" \
    #     atclone"mkdir -p plugins; cd plugins; ln -sfn ../. osx"
    # zplugin snippet OMZ::plugins/osx
    zplugin ice wait"0" lucid
    zplugin snippet OMZ::plugins/iterm2/iterm2.plugin.zsh
elif [[ "$OSTYPE" == 'cygwin' ]]; then
    zplugin ice wait"0" lucid
    zplugin snippet OMZ::plugins/cygwin/cygwin.plugin.zsh
fi

zplugin snippet OMZ::lib/git.zsh
# Load completion library for those sweet [tab] squares
zplugin snippet OMZ::lib/completion.zsh
# Up -> History search!
zplugin snippet OMZ::lib/key-bindings.zsh
# History defaults
zplugin snippet OMZ::lib/history.zsh
# Adds useful aliases for things dealing with directories
zplugin snippet OMZ::lib/directories.zsh

zplugin ice wait"0" blockf lucid
zplugin light zsh-users/zsh-completions

# zplug "hchbaw/auto-fu.zsh"
zplugin ice wait"0" lucid
zplugin light zsh-users/zsh-history-substring-search

    # Bind UP and DOWN arrow keys for substring search.
    zmodload zsh/terminfo
    bindkey "$terminfo[cuu1]" history-substring-search-up
    bindkey "$terminfo[cud1]" history-substring-search-down

    bindkey -M emacs '^P' history-substring-search-up
    bindkey -M emacs '^N' history-substring-search-down

    bindkey -M vicmd 'k' history-substring-search-up
    bindkey -M vicmd 'j' history-substring-search-down

zplugin ice wait"0" atload"unalias grv" lucid
zplugin snippet OMZ::plugins/git/git.plugin.zsh

zplugin ice wait"0" lucid
zplugin snippet OMZ::plugins/colored-man-pages/colored-man-pages.plugin.zsh
# zplug "zlsun/solarized-man"

# OS - Command Not Found Helper
zplugin ice wait"0" lucid
zplugin snippet OMZ::plugins/command-not-found/command-not-found.plugin.zsh

# Python
zplugin ice wait"0" if'[[ -n "$commands[pip]" ]]' lucid
zplugin snippet OMZ::plugins/pip/pip.plugin.zsh
zplugin ice wait"0" if'[[ -n "$commands[python]" ]]' lucid
zplugin snippet OMZ::plugins/python/python.plugin.zsh
if type workon &>/dev/null; then
    zplugin ice wait"0" lucid
    zplugin snippet OMZ::plugins/virtualenv/virtualenv.plugin.zsh
    unset VIRTUAL_ENV_DISABLE_PROMPT

    # mkvenv创建virtualenv，在cd时自动切换
    zplugin ice wait"0" lucid
    zplugin snippet OMZ::plugins/virtualenvwrapper/virtualenvwrapper.plugin.zsh
fi

# docker
zplugin ice as"completion" if'[[ -n "$commands[docker]" ]]'
zplugin snippet https://github.com/docker/cli/raw/master/contrib/completion/zsh/_docker

# npm
zplugin ice wait"0" if'[[ -n "$commands[npm]" ]]' lucid
zplugin snippet OMZ::plugins/npm/npm.plugin.zsh

zplugin ice wait"0" if'[[ -n "$commands[sudo]" ]]' lucid
zplugin snippet OMZ::plugins/sudo/sudo.plugin.zsh

# 如果使用的命令有定义alias，会进行提醒
zplugin ice wait"0" lucid
zplugin light djui/alias-tips

zplugin ice wait"1" atload"_zsh_autosuggest_start" lucid
zplugin light zsh-users/zsh-autosuggestions

zplugin ice wait"1" lucid
zplugin load zdharma/history-search-multi-word

zplugin ice wait"5" atinit"ZPLGM[COMPINIT_OPTS]=-C; zpcompinit; zpcdreplay" lucid
zplugin light zdharma/fast-syntax-highlighting

# Utils
zplugin ice wait"1" lucid mv"httpstat.sh -> httpstat" pick"httpstat" as"program"
zplugin snippet https://github.com/b4b4r07/httpstat/blob/master/httpstat.sh

zplugin ice wait"1"
zplugin light mollifier/cd-gitroot

## Theme
setopt promptsubst

#zplugin light NicoSantangelo/Alpharized

### Pure Theme (loaded using async)
#zplugin ice pick"async.zsh" src"pure.zsh"
#zplugin light sindresorhus/pure

#zplugin light agnoster/agnoster-zsh-theme

source "$DOTFILES_ROOT/zsh/scripts/powerlevel9k.conf.zsh"
zplugin light bhilburn/powerlevel9k

#zplugin snippet OMZ::themes/dstufft.zsh-theme

# ############
# # 一些缺省值
# zplug "willghatch/zsh-saneopt"

# # util used by some plugins
# zplug "mafredri/zsh-async"

# # export NVM_LAZY_LOAD=true
# # zplug "lukechilds/zsh-nvm"

# # VCS 
# zplug "plugins/gitfast", from:oh-my-zsh, if:"(( $+commands[git] ))"

