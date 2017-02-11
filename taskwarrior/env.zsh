if [ -f /usr/local/share/taskwarrior/scripts/zsh/_task ]; then
    fpath=($fpath /usr/local/share/taskwarrior/scripts/zsh)
elif [ -f /usr/local/share/doc/task/scripts/zsh/_task ]; then
    fpath=($fpath /usr/local/share/doc/task/scripts/zsh)
elif [ -f /usr/share/doc/task/scripts/zsh/_task ]; then
    fpath=($fpath /usr/share/doc/task/scripts/zsh)
fi
