timestamp() {
    while [ $# -gt 0 ]
    do
        timestamp=$1
        date -d @$((timestamp / 1000000)) +"%Y-%m-%d %T".$((timestamp % 1000000))
        shift
    done
}

epochtime() {
    while [ $# -gt 0 ]
    do
        epochtime=$1
        date -d @$((epochtime / 1000)) +"%Y-%m-%d %T".$((epochtime % 1000))
        shift
    done
}

time_t() {
    while [ $# -gt 0 ]
    do
        time_t=$1
        date -d @$((time_t)) +"%Y-%m-%d %T"
        shift
    done
}

