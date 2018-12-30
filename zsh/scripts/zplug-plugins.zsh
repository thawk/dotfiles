export ZPLUG_HOME="${HOME}/.zplug"
if [ ! -f ${ZPLUG_HOME}/repos/zplug/zplug/init.zsh ]
then
    echo 'Cloning zplug...'
    mkdir -p "${ZPLUG_HOME}/repos/zplug"
    git clone https://github.com/zplug/zplug.git "${ZPLUG_HOME}/repos/zplug/zplug"
    if [ "$?" -ne "0" ]; then
        echo "Failed to clone zplug!"
        echo 'Execute the following command get zplug:' > /dev/stderr
        echo "    git clone https://github.com/zplug/zplug.git '${ZPLUG_HOME}/repos/zplug/zplug'" > /dev/stderr
        return 1
    fi
fi

# load zplug
source "${ZPLUG_HOME}/repos/zplug/zplug/init.zsh"

# Tmux
zplug "plugins/tmux", from:oh-my-zsh, if:"(( $+commands[tmux] ))"

# 一些缺省值
zplug "willghatch/zsh-saneopt"

# Load completion library for those sweet [tab] squares
zplug "lib/completion", from:oh-my-zsh
# Up -> History search!
zplug "lib/key-bindings", from:oh-my-zsh
# History defaults
zplug "lib/history", from:oh-my-zsh
# Adds useful aliases for things dealing with directories
zplug "lib/directories", from:oh-my-zsh

# util used by some plugins
zplug "mafredri/zsh-async"

# Python
zplug "plugins/pip", from:oh-my-zsh, if:"(( $+commands[pip] ))"
zplug "plugins/python", from:oh-my-zsh, if:"(( $+commands[python] ))"
zplug "plugins/docker", from:oh-my-zsh, if:"(( $+commands[docker] ))"
# mkvenv创建virtualenv，在cd时自动切换
zplug "plugins/virtualenvwrapper", from:oh-my-zsh, if:"[[ -d $HOME/.virtualenvs ]]"
# zplug "MichaelAquilina/zsh-autoswitch-virtualenv"
# 用pip-app安装的每个pip都有自己的virtualenv
zplug "sharat87/pip-app", use:pip-app.sh, if:"(( $+commands[pip] ))"

# zplug "jeffwalter/zsh-plugin-rvm-auto", if:"[ -f ~/.rvm/bin/rvm ]"

# Javascript
zplug "plugins/npm", from:oh-my-zsh, if:"(( $+commands[npm] ))"
# export NVM_LAZY_LOAD=true
# zplug "lukechilds/zsh-nvm"

# ZAW
# zplug "zsh-users/zaw", use:zaw.zsh
# zplug "junkblocker/calibre-zaw-source", on:"zsh-users/zaw", if:"(( $+commands[calibredb] ))", defer:1

# Misc
# <ESC><ESC>为当前命令加上sudo
zplug "hcgraf/zsh-sudo", if:"(( $+commands[sudo] ))"

# 如果使用的命令有定义alias，会进行提醒
zplug "djui/alias-tips"

# VCS 
zplug "plugins/gitfast", from:oh-my-zsh, if:"(( $+commands[git] ))"

# GeekNote: cmdline for evernote
zplug "plugins/geeknote", from:oh-my-zsh, if:"(( $+commands[geeknote] ))"

# 外观调整
zplug "zlsun/solarized-man"
zplug "jreese/zsh-titles"

# 自动建议、补全
# Very cool plugin that generates zsh completion functions for commands
# if they have getopt-style help text. It doesn't generate them on the fly,
# you'll have to explicitly generate a completion, but it's still quite cool.
# 用gencomp命令生成补全文件。
# zplug "RobSis/zsh-completion-generator"

# 放到oh-my-zsh/lib/key-bindings后面执行，以便保证能绑定<C-R>
zplug "zdharma/history-search-multi-word", defer:1
# zplug "hchbaw/auto-fu.zsh"
zplug "zsh-users/zsh-autosuggestions"
zplug "zsh-users/zsh-completions"
zplug "zsh-users/zsh-syntax-highlighting", defer:2
zplug "zsh-users/zsh-history-substring-search", defer:2

# themes
# zplug "themes/agnoster", from:oh-my-zsh, as:theme
zplug "janernsting/dotfiles", use:"zsh/custom/themes/custom-agnoster.zsh-theme", as:theme

zplug "b4b4r07/httpstat", \
    as:command, \
    use:'(*).sh', \
    rename-to:'$1'

zplug 'zplug/zplug', hook-build:'zplug --self-manage'

# Install plugins if there are plugins that have not been installed
if ! zplug check ; then
    printf "Install? [y/N]: "
    if read -q; then
        echo; zplug install
    fi
fi

# Then, source plugins and add commands to $PATH
zplug load

# Bind UP and DOWN arrow keys for substring search.
if zplug check zsh-users/zsh-history-substring-search; then
    zmodload zsh/terminfo
    bindkey "$terminfo[cuu1]" history-substring-search-up
    bindkey "$terminfo[cud1]" history-substring-search-down

    bindkey -M emacs '^P' history-substring-search-up
    bindkey -M emacs '^N' history-substring-search-down

    bindkey -M vicmd 'k' history-substring-search-up
    bindkey -M vicmd 'j' history-substring-search-down
fi
