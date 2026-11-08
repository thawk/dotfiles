if [ -d ~/.vim/bundle/base16-shell ]; then
    if [[ ":$PATH:" != *":$HOME/.vim/bundle/base16-shell:"* ]]; then
        export PATH="$PATH:$HOME/.vim/bundle/base16-shell"
    fi
fi

