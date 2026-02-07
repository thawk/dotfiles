alias aph="env \${MY_HTTP_PROXY:+http_proxy=http://\${MY_HTTP_PROXY} https_proxy=http://\${MY_HTTP_PROXY} }all_proxy=socks5://\${MY_SOCKS5_PROXY:-127.0.0.1:1080} "
alias aphl="env \${LOCAL_HTTP_PROXY:+http_proxy=http://\${LOCAL_HTTP_PROXY} https_proxy=http://\${LOCAL_HTTP_PROXY} }all_proxy=socks5://\${LOCAL_SOCKS5_PROXY:-127.0.0.1:1080} "
# no proxy
alias np="env http_proxy= https_proxy= all_proxy= GIT_SSH_COMMAND= "
alias stripcolors='sed -r "s/\x1b\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g"'
#alias myip='dig +short myip.opendns.com @resolver1.opendns.com'
alias myip="curl -s 'https://api.whatismyip.com/wimi.php' -X POST -H 'Origin: https://www.whatismyip.com' | sed 's/^.*\"ip\":\"\([^\"]*\)\".*$/\1\n/'"
alias 1='fg %1'
alias 2='fg %2'
alias 3='fg %3'
alias 11='bg %1'
alias 22='bg %2'
alias 33='bg %3'
