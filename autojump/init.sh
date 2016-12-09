shell="${SHELL##*/}"

for prefix in /usr /usr/local
do
    script="${prefix}/share/autojump/autojump.${shell}"
    if [ -e "$script" ]
    then
        source "$script"
        break
    fi
done

