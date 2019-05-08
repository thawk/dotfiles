timestamp() {
    local epoch=
    local subsecs=

    while [ $# -gt 0 ]
    do
        ts=$1
        if [[ $ts -lt 10000000000 ]]; then
            epoch=ts
        elif [[ $ts -lt 10000000000000 ]]; then
            epoch=$((ts / 1000))
            subsecs=.$(printf "%03d" $((ts % 1000)))
        else
            epoch=$((ts / 1000000))
            subsecs=.$(printf "%06d" $((ts % 1000000)))
        fi

        if [[ "$OSTYPE" == "darwin"* ]]; then
            date -r ${epoch} +"%Y-%m-%d %T"${subsecs}
        else
            date -d @${epoch} +"%Y-%m-%d %T"${subsecs}
        fi

        shift
    done
}

