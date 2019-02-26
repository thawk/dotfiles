timestamp() {
    while [ $# -gt 0 ]
    do
        ts=$1
        if [[ $ts -lt 10000000000 ]]; then
            date -d @$((ts)) +"%Y-%m-%d %T"
        elif [[ $ts -lt 10000000000000 ]]; then
            date -d @$((ts / 1000)) +"%Y-%m-%d %T".$(printf "%03d" $((ts % 1000)))
        else
            date -d @$((ts / 1000000)) +"%Y-%m-%d %T".$(printf "%03d" $((ts % 1000000)))
        fi
        shift
    done
}

