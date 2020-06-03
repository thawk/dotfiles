ansiesc() {
    sed -e 's/\[[0-9;]\+m//g'
}

vman () {
    vim +"set ft=man" +"Man $*"
}

setproxy () {
    # 如果命令行没有提供代理地址，使用MY_SOCKS5_PROXY的值，如果也没有设置就用127.0.0.1:1080
    local proxy=${1:-${MY_SOCKS5_PROXY:-127.0.0.1:1080}}
    export all_proxy=socks5://${MY_SOCKS5_PROXY:-127.0.0.1:1080}
    export GIT_SSH_COMMAND="ssh -o ProxyCommand=\"nc -X 5 -x ${MY_SOCKS5_PROXY:-127.0.0.1:1080} %h %p\""
}
