if [ ! -z "$MSYSTEM" ]
then    # MSYS2
    alias ping="/bin/winpty ping"
    alias netstat="/bin/winpty netstat"
    alias nslookup="/bin/winpty nslookup"
    alias ipconfig="/bin/winpty ipconfig"

    # complete hard drives in msys2
    drives=$(mount | sed -rn 's#^[A-Z]: on /([a-z]).*#\1#p' | tr '\n' ' ')
    zstyle ':completion:*' fake-files /: "/:$drives"
    unset drives
fi

