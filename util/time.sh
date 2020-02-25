timestamp() {
    local epoch=
    local subsecs=

    if [[ $# -eq 0 ]]; then
        # Current time
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
        # Cnvert time from parameters
        while [ $# -gt 0 ]
        do
            ts=$1
            if [[ $ts -lt 253402300800 ]]; then
                epoch=$ts
                subsecs=
            elif [[ $ts -lt 253402300800000 ]]; then
                epoch=$((ts / 1000))
                subsecs=.$(printf "%03d" $((ts % 1000)))
            elif [[ $ts -lt 64060588800000000 ]]; then
                epoch=$((ts / 1000000))
                subsecs=.$(printf "%06d" $((ts % 1000000)))
            else
                # FILETIME, 100ns count from 1601-01-01, 109205 days before 1900-01-01,
                # 25569 more days before 1970-01-01
                epoch=$((ts / 10000000 - (109205 + 25569) * 24 * 60 * 60))
                subsecs=.$(printf "%07d" $((ts % 10000000)))
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
