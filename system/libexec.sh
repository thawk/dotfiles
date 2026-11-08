if [ -d "$HOME/libexec" ]
then
    for f in "$HOME/libexec/"*.bash
    do
        source "$f"
    done

    if find "$HOME/libexec" -name "*.so" -quit
    then
        if [[ ":$LD_LIBRARY_PATH:" != *":$HOME/libexec:"* ]]
        then
            export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}$HOME/libexec"
        fi
    fi
fi

