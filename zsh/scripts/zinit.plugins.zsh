ZINIT_HOME="${ZDOTDIR:-$HOME}/.zinit"

if [[ ! -f "$ZINIT_HOME/bin/zinit.zsh" ]]; then
    print -P "%F{33}▓▒░ %F{220}Installing DHARMA Initiative Plugin Manager (zdharma/zinit)…%f"
    command mkdir -p "${ZINIT_HOME}" && command chmod g-rwX "${ZINIT_HOME}"
    command git clone https://github.com/zdharma/zinit "${ZINIT_HOME}/bin" && \
        print -P "%F{33}▓▒░ %F{34}Installation successful.%f" || \
        print -P "%F{160}▓▒░ The clone has failed.%f"
fi

# load zinit
source "$ZINIT_HOME/bin/zinit.zsh"
autoload -Uz _zinit
(( ${+_comps} )) && _comps[zinit]=_zinit

# Tmux
zinit ice svn if'[[ -n "$commands[tmux]" ]]' lucid
# zinit ice if'[[ -n "$commands[tmux]" ]]' lucid
zinit snippet OMZ::plugins/tmux

# OS specific plugins
if [[ "$OSTYPE" == "darwin"* ]]; then
    # zinit ice wait"0" lucid atinit"local ZSH=\$PWD" \
    #     atclone"mkdir -p plugins; cd plugins; ln -sfn ../. osx"
    # zinit snippet OMZ::plugins/osx
    zinit wait"0" lucid for \
        OMZ::plugins/iterm2/iterm2.plugin.zsh
fi

# completion.zsh: Load completion library for those sweet [tab] squares
# key-bindings.zsh: Up -> History search!
# history.zsh: History defaults
# directories.zsh: Adds useful aliases for things dealing with directories
zinit wait lucid for \
    OMZ::lib/git.zsh \
    OMZ::lib/completion.zsh \
    OMZ::lib/key-bindings.zsh \
    OMZ::lib/history.zsh \
    OMZ::lib/directories.zsh \
    OMZ::plugins/colored-man-pages/colored-man-pages.plugin.zsh \
    atload"unalias grv" OMZ::plugins/git/git.plugin.zsh


zinit ice wait"0" blockf lucid
zinit light zsh-users/zsh-completions

# zplug "hchbaw/auto-fu.zsh"
zinit ice wait"0" lucid
zinit light zsh-users/zsh-history-substring-search

    # Bind UP and DOWN arrow keys for substring search.
    zmodload zsh/terminfo
    bindkey "$terminfo[cuu1]" history-substring-search-up
    bindkey "$terminfo[cud1]" history-substring-search-down

    bindkey -M emacs '^P' history-substring-search-up
    bindkey -M emacs '^N' history-substring-search-down

    bindkey -M vicmd 'k' history-substring-search-up
    bindkey -M vicmd 'j' history-substring-search-down

# OS - thefuck
zinit ice wait"0" if'[[ -n "$commands[fuck]" ]]' lucid
zinit snippet OMZ::plugins/thefuck/thefuck.plugin.zsh

# Python
zinit wait"0" lucid for \
    if'[[ -n "$commands[pip]" ]]' OMZ::plugins/pip/pip.plugin.zsh \
    if'[[ -n "$commands[python]" ]]' OMZ::plugins/python/python.plugin.zsh

zinit wait"0" lucid if'type workon &> /dev/null' for \
    atload"unset VIRTUAL_ENV_DISABLE_PROMPT" OMZ::plugins/virtualenv/virtualenv.plugin.zsh \
    OMZ::plugins/virtualenvwrapper/virtualenvwrapper.plugin.zsh

# docker
zinit ice wait as"completion" if'[[ -n "$commands[docker]" ]]' lucid
zinit snippet https://github.com/docker/cli/raw/master/contrib/completion/zsh/_docker

## sudo
#zinit ice wait"0" if'[[ -n "$commands[sudo]" ]]' lucid
#zinit snippet OMZ::plugins/sudo/sudo.plugin.zsh

zinit wait"1" lucid light-mode for \
    djui/alias-tips \
    atload"_zsh_autosuggest_start" zsh-users/zsh-autosuggestions \
    zdharma/history-search-multi-word \
    atinit"zpcompinit; zpcdreplay" zdharma/fast-syntax-highlighting

# Utils
zinit ice wait"1" lucid mv"httpstat.sh -> httpstat" pick"httpstat" as"program"
zinit snippet https://github.com/b4b4r07/httpstat/blob/master/httpstat.sh

# zinit ice wait"1" lucid
# zinit light mollifier/cd-gitroot

zinit wait"1" lucid light-mode for \
    supercrabtree/k

## Theme
setopt promptsubst
PS1="READY >" # provide a nice prompt till the theme loads

#zinit light NicoSantangelo/Alpharized

### Pure Theme (loaded using async)
#zinit ice pick"async.zsh" src"pure.zsh"
#zinit light sindresorhus/pure

#zinit light agnoster/agnoster-zsh-theme

source "$DOTFILES_ROOT/zsh/scripts/powerlevel9k.conf.zsh"
#zinit light bhilburn/powerlevel9k
zinit light romkatv/powerlevel10k

#zinit ice nocompletions
#zinit load robobenklein/p10k

#zinit snippet OMZ::themes/dstufft.zsh-theme

# ############
# # 一些缺省值
# zplug "willghatch/zsh-saneopt"

# # util used by some plugins
# zplug "mafredri/zsh-async"

# # export NVM_LAZY_LOAD=true
# # zplug "lukechilds/zsh-nvm"

# # VCS 
# zplug "plugins/gitfast", from:oh-my-zsh, if:"(( $+commands[git] ))"

