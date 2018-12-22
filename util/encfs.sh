if type encfs &> /dev/null
then
    em() {
        if [ -z "$1" ]; then
            echo "$0 <target>"
            return
        fi

        parent="$(cd "$(dirname "$1")" && pwd -P)"
        base=$(basename "$1")

        if [[ "${base}" == .* ]]
        then  # begin with a dot
            src="${parent}/${base}"
            dst="${parent}/${base#.}"
        else
            src="${parent}/.${base}"
            dst="${parent}/${base}"
        fi

        for f in "${src}/.encfs"*.xml
        do
            if [ ! -f "$f" ]
            then
                echo "'$src' not exists or not a encfs directory!"
                return
            fi
            break
        done

        mkdir -p "${dst}" && encfs "${src}" "${dst}"
    }

    um() {
        if [ -z "$1" ]; then
            # umount all
            if mount | grep "^encfs@" &> /dev/null; then
                mount | grep "^encfs@" | cut -d' ' -f3 | while read d
                do
                    encfs -u "${d}"
                    rm -d "${d}"
                done
            fi
        else
            encfs -u "$1"
            rm -d "$1"
        fi
    }

    alias mp="em '$HOME/my/private'"
    alias ump="um '$HOME/my/private'"
fi
