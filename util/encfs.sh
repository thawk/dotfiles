if type encfs &> /dev/null
then
    em() {
        if [ -z "$1" ]; then
            echo "$0 <target>"
            return
        fi

        parent="$(cd "$(dirname "$1")" && pwd -P)"
        dst="${parent}/$(basename "$1")"
        src="${parent}/.$(basename "$1")"

        if [ ! -d "$src" ]; then
            echo "'$src' not exists!"
            return
        fi

        mkdir -p "${dst}" && encfs "${src}" "${dst}"
    }

    um() {
        encfs -u "$1"
        rm -d "$1"
    }

    alias mp="em '$HOME/my/private'"
    alias ump="um '$HOME/my/private'"
fi
