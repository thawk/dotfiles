ZI_HOME="${ZDOTDIR:-$HOME}/.zi"

if [[ ! -f "$ZI_HOME/bin/zi.zsh" ]]; then
    if ! (( $+commands[git] )); then
        # Doesn't has git, can't install ZI, exiting
        return
    fi

    print -P "%F{33}▓▒░ %F{220}Installing z-shell/zi …%f"
    command mkdir -p "${ZI_HOME}" && command chmod g-rwX "${ZI_HOME}"
    command git clone https://github.com/z-shell/zi "${ZI_HOME}/bin" && \
        print -P "%F{33}▓▒░ %F{34}Installation successful.%f" || \
        print -P "%F{160}▓▒░ The clone has failed.%f"
fi

# load zi
source "$ZI_HOME/bin/zi.zsh"
autoload -Uz _zi
(( ${+_comps} )) && _comps[zi]=_zi

## Tmux
#zi ice svn if'[[ -n "$commands[tmux]" ]]' lucid
#zi snippet OMZ::plugins/tmux

# OS specific plugins
if [[ "$OSTYPE" == "darwin"* ]]; then
    # zi ice wait"0" lucid atinit"local ZSH=\$PWD" \
    #     atclone"mkdir -p plugins; cd plugins; ln -sfn ../. osx"
    # zi snippet OMZ::plugins/osx
    zi wait"0" lucid for \
        OMZ::plugins/iterm2/iterm2.plugin.zsh
fi

# completion.zsh: Load completion library for those sweet [tab] squares
# key-bindings.zsh: Up -> History search!
# history.zsh: History defaults
# directories.zsh: Adds useful aliases for things dealing with directories
zi wait lucid for \
    OMZ::lib/git.zsh \
    OMZ::lib/completion.zsh \
    OMZ::lib/key-bindings.zsh \
    OMZ::lib/history.zsh \
    OMZ::lib/directories.zsh \
    OMZ::plugins/colored-man-pages/colored-man-pages.plugin.zsh \
    atload"unalias grv" OMZ::plugins/git/git.plugin.zsh

zi ice wait"0" blockf lucid
zi light zsh-users/zsh-completions

# zplug "hchbaw/auto-fu.zsh"
zi ice wait"0" lucid
zi light zsh-users/zsh-history-substring-search

    # Bind UP and DOWN arrow keys for substring search.
    zmodload zsh/terminfo
    bindkey "$terminfo[cuu1]" history-substring-search-up
    bindkey "$terminfo[cud1]" history-substring-search-down

    bindkey -M emacs '^P' history-substring-search-up
    bindkey -M emacs '^N' history-substring-search-down

    bindkey -M vicmd 'k' history-substring-search-up
    bindkey -M vicmd 'j' history-substring-search-down

# OS - thefuck
zi ice wait"0" if'[[ -n "$commands[fuck]" ]]' lucid
zi snippet OMZ::plugins/thefuck/thefuck.plugin.zsh

# Python
zi wait"0" lucid for \
    if'[[ -n "$commands[pip]" ]]' OMZ::plugins/pip/pip.plugin.zsh \
    if'[[ -n "$commands[python]" ]]' OMZ::plugins/python/python.plugin.zsh

zi wait"0" lucid if'type workon &> /dev/null' for \
    atload"unset VIRTUAL_ENV_DISABLE_PROMPT" OMZ::plugins/virtualenv/virtualenv.plugin.zsh \
    OMZ::plugins/virtualenvwrapper/virtualenvwrapper.plugin.zsh

# docker
zi ice wait as"completion" if'[[ -n "$commands[docker]" ]]' lucid
zi snippet https://github.com/docker/cli/raw/master/contrib/completion/zsh/_docker

## sudo
#zi ice wait"0" if'[[ -n "$commands[sudo]" ]]' lucid
#zi snippet OMZ::plugins/sudo/sudo.plugin.zsh

# H-S-MW: history-search-multi-word
zi wait"1" lucid light-mode for \
    djui/alias-tips \
    atload"_zsh_autosuggest_start" zsh-users/zsh-autosuggestions \
    z-shell/H-S-MW \
    atinit"ZI[COMPINIT_OPTS]=-C; zicompinit; zicdreplay" z-shell/F-Sy-H

## Utils
#zi ice wait"1" lucid mv"httpstat.sh -> httpstat" pick"httpstat" as"program"
#zi snippet https://github.com/b4b4r07/httpstat/blob/master/httpstat.sh

# zi ice wait"1" lucid
# zi light mollifier/cd-gitroot

zi wait"1" lucid light-mode for \
    supercrabtree/k

## Theme
setopt promptsubst
PS1="READY >" # provide a nice prompt till the theme loads

#zi light NicoSantangelo/Alpharized

### Pure Theme (loaded using async)
#zi ice pick"async.zsh" src"pure.zsh"
#zi light sindresorhus/pure

#zi light agnoster/agnoster-zsh-theme

# source "$DOTFILES_ROOT/zsh/scripts/powerlevel9k.conf.zsh"
source "$DOTFILES_ROOT/zsh/scripts/p10k.conf.zsh"
#zi light bhilburn/powerlevel9k
zi light romkatv/powerlevel10k

#zi ice nocompletions
#zi load robobenklein/p10k

#zi snippet OMZ::themes/dstufft.zsh-theme

# ############
# # 一些缺省值
# zplug "willghatch/zsh-saneopt"

# # util used by some plugins
# zplug "mafredri/zsh-async"

# # export NVM_LAZY_LOAD=true
# # zplug "lukechilds/zsh-nvm"

# # VCS 
# zplug "plugins/gitfast", from:oh-my-zsh, if:"(( $+commands[git] ))"

