# Use a local proxy
alias ap="env all_proxy=socks5://\${MY_SOCKS5_PROXY:-127.0.0.1:1080} GIT_SSH_COMMAND='ssh -o ProxyCommand=\"nc -X 5 -x \${MY_SOCKS5_PROXY:-127.0.0.1:1080} %h %p\"' "
#alias aph="env all_proxy=socks5://\${MY_SOCKS5_PROXY:-127.0.0.1:1080} "
alias aph="all_proxy=socks5://\${MY_SOCKS5_PROXY:-127.0.0.1:1080} "
# Use a local proxy
alias apl="env all_proxy=socks5://127.0.0.1:1080 GIT_SSH_COMMAND='ssh -o ProxyCommand=\"nc -X 5 -x 127.0.0.1:1080 %h %p\"' "
# alias aphl="env all_proxy=socks5://127.0.0.1:1080 "
alias aphl="all_proxy=socks5://127.0.0.1:1080 "
# no proxy
alias np="env all_proxy= GIT_SSH_COMMAND= "
alias stripcolors='sed -r "s/\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g"'
alias myip='dig +short myip.opendns.com @resolver1.opendns.com'
alias 1='fg %1'
alias 2='fg %2'
alias 3='fg %3'
alias 11='bg %1'
alias 22='bg %2'
alias 33='bg %3'
