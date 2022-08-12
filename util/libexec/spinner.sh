spinner()
{
    local pid=$! # Process Id of the previous running command
    local delay=0.5
    local spin

    spin="-\\|/"
    #spin="←↖↑↗→↘↓↙"

    echo -ne "\r $*"

    last_spinner=${last_spinner:-0}
    while kill -0 $pid 2> /dev/null; do
        if [[ "$last_spinner" -ge "${#spin}" ]]; then
            last_spinner=0
        fi

        echo -ne "\r${spin:$last_spinner:1}"
        sleep $delay

        last_spinner=$((last_spinner+1))
    done
    echo -ne "\r "
}

get_progress_str()
{
    local count=$1
    local total=$2
    local msg=$3

    local width=30
    local empty
    empty="$(printf '[%*s]' "$width" "")"
    local pstr
    pstr="$(printf '[%*s]' "$width" ""| tr ' ' '=')"

    pd=$(( count * $((width+2)) / total ))
    printf "%3d.%1d%% %s%s %s" $(( count * 100 / total )) $(( (count * 1000 / total) % 10 )) "${pstr:0:$pd}" "${empty:$pd}" "$msg"
}

progress()
{
    printf "\r%s" "$(get_progress_str "$@")"
}

#for ((i=1; i<=5; ++i)); do
#    sleep 1s
#    progress $i 5 "filename-$i"
#done

#echo ""
#for ((i=1; i<=5; ++i)); do
#    sleep 1s &
#    spinner "$(get_progress_str $i 5 "filename-$i")"
#done

