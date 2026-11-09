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

# docker
zi ice wait as"completion" if'[[ -n "$commands[docker]" ]]' lucid
zi snippet https://github.com/docker/cli/raw/master/contrib/completion/zsh/_docker

# H-S-MW: history-search-multi-word
# F-Sy-H: Feature-rich Syntax Highlighting for Zsh
zi wait"1" lucid light-mode for \
    djui/alias-tips \
    z-shell/H-S-MW \
    atinit"ZI[COMPINIT_OPTS]=-C; zicompinit; zicdreplay" z-shell/F-Sy-H

zi wait"1" lucid light-mode for \
    atload"_zsh_autosuggest_start" zsh-users/zsh-autosuggestions

zi wait"1" lucid light-mode for \
    supercrabtree/k

# git dsf 显示更友好的diff信息。
# 也可把diff重定向到diff-so-fancy获得友好的diff信息。
if ! (( $+commands[git] )); then
    zi ice as'null' sbin'bin/*'
    zi light z-shell/zsh-diff-so-fancy
fi

## Theme
setopt promptsubst
PS1="READY >" # provide a nice prompt till the theme loads

# source "$DOTFILES_ROOT/zsh/scripts/powerlevel9k.conf.zsh"
source "$DOTFILES_ROOT/zsh/scripts/p10k.conf.zsh"
#zi light bhilburn/powerlevel9k
zi light romkatv/powerlevel10k

