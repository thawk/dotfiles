alias -g TODAY="\$(date +%Y-%m-%d)"
# Use a local proxy
alias ap="env all_proxy=socks://127.0.0.1:1080 GIT_SSH_COMMAND='ssh -o ProxyCommand=\"nc -X 5 -x 127.0.0.1:1080 %h %p\"'"
