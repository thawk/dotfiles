if [ -d "$HOME/libexec" ]
then
    for f in "$HOME/libexec/"*.bash
    do
        source "$f"
    done

    if find "$HOME/libexec" -name "*.so" -quit
    then
        if [ -z "$LD_LIBRARY_PATH" ]
        then
            export LD_LIBRARY_PATH="$HOME/libexec"
        else
            export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/libexec"
        fi
    fi
fi

