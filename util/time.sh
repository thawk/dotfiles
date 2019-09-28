timestamp() {
    local epoch=
    local subsecs=

    if [[ $# -eq 0 ]]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            if type python &> /dev/null; then
                python -c 'from time import time; print(int(round(time() * 1000000)))'
            else
                date +"%s000000"
            fi
        else
            date +"%s%N"
        fi
    else
        while [ $# -gt 0 ]
        do
            ts=$1
            if [[ $ts -lt 10000000000 ]]; then
                epoch=$ts
                subsecs=
            elif [[ $ts -lt 10000000000000 ]]; then
                epoch=$((ts / 1000))
                subsecs=.$(printf "%03d" $((ts % 1000)))
            else
                epoch=$((ts / 1000000))
                subsecs=.$(printf "%06d" $((ts % 1000000)))
            fi

            if [[ "$OSTYPE" == "darwin"* ]]; then
                date -u -r ${epoch} +"%Y-%m-%d %T"${subsecs}" UTC"
            else
                date --utc -d @${epoch} +"%Y-%m-%d %T"${subsecs}" UTC"
            fi

            shift
        done
    fi
}

(type ts &> /dev/null) || alias ts=timestamp
