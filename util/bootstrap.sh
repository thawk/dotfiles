#!/usr/bin/env bash
# Time: 2023-06-01 06:21:02

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "util"
alias_file="$(create_plugin_file alias.sh)"
editor_file="$(create_plugin_file editor.sh)"

# Detect netcat executable
netcat=
if type netcat &> /dev/null; then
    netcat=netcat
elif type nc &> /dev/null; then
    netcat=nc
fi

proxy_alias() {
    netcat="$1"
    name="$2"
    proxy="$3"

    echo "alias ${name}='env all_proxy=socks5://\${${proxy}:-127.0.0.1:1080} GIT_SSH_COMMAND=\"ssh -o ProxyCommand=\\\"${netcat} -x \${${proxy}:-127.0.0.1:1080} %h %p\\\"\"'"
}

if [[ -n "$netcat" ]]; then
    proxy_alias "$netcat" ap MY_SOCKS5_PROXY >> "${alias_file}"
    proxy_alias "$netcat" apl LOCAL_SOCKS5_PROXY >> "${alias_file}"
else
    # no netcat found, only support HTTP proxy
    echo "alias ap=aph" >> "${alias_file}"
    echo "alias apl=aphl" >> "${alias_file}"
fi

# 如果有vim则用vim。否则用vi。在有vim时，如果没有vi，将vi定义为vim的alias
if type nvim &> /dev/null ; then
    echo "export EDITOR='nvim'" >> "${editor_file}"
    # echo "export MANPAGER=\"nvim +'set ft=man' -\"" >> "${env_file}"

    # 在MacOS下，使用neovim代替vim
    if ! type vim &> /dev/null || [[ "$OSTYPE" == "darwin"* ]] ; then
        echo "alias vim=nvim" >> "${editor_file}"
    fi

    type vi &> /dev/null || echo "alias vi=nvim" >> "${editor_file}"

    # viu不使用vim配置，适合打开大文件
    echo "alias viu='nvim -u /dev/null'" >> "${editor_file}"
elif type vim &> /dev/null ; then
    echo "export EDITOR='vim'" >> "${editor_file}"
    # echo "export MANPAGER=\"vim +'set ft=man' -\"" >> "${env_file}"
    type vi &> /dev/null || echo "alias vi=vim" >> "${editor_file}"

    # viu不使用vim配置，适合打开大文件
    echo "alias viu='vim -u /dev/null'" >> "${editor_file}"
elif type vi &> /dev/null ; then
    echo "export EDITOR='vi'" >> "${editor_file}"
fi

