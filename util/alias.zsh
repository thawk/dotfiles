alias -g TODAY="\$(date +%Y-%m-%d)"
# Use a local proxy
alias ap="env all_proxy=socks5://${MY_SOCKS5_PROXY:-127.0.0.1:1080} GIT_SSH_COMMAND='ssh -o ProxyCommand=\"nc -X 5 -x ${MY_SOCKS5_PROXY:-127.0.0.1:1080} %h %p\"'"
