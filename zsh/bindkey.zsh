# M-m 拷贝上一个参数。可先 M-. 去到要用的行，再用 M-m
autoload -Uz copy-earlier-word
zle -N copy-earlier-word
bindkey "^[m" copy-earlier-word
