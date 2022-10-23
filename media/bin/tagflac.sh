#!/usr/bin/env bash

set -e

EchoUsage()
{
    echo "
Usage: $(basename "$0") [options] [--] <flac files>

    Options:
        -h|help             Display this message
        -v|verbose          Display more verbose log
        -n|dry-run          Display the command, don't execute
        -g|genre <val>      Set GENRE tag
        -c|composer <val>   Set ARTIST/COMPOSER tag
        -a|album <val>      Set ALBUM tag
        -p|performer <val>  Set PERFORMER tag
        -C|comment <val>    Set COMMENT tag
        -y|year <val>       Set YEAR tag
        -r|renumber [start] Renumber track, started from start (default to 1)         
" >&2
}

VERBOSE=
DRYRUN=

args=()
comment=
tracknum=

while getopts ":hvng:c:a:p:C:y:r:" opt; do
    case $opt in
        h|help)
            EchoUsage
            exit 0
            ;;
        v|verbose)
            VERBOSE="${VERBOSE}1"
            ;;
        n|dry-run)
            DRYRUN="1"
            ;;
        g|genre)
            args=( "${args[@]}" "--remove-tag=GENRE" "--set-tag=GENRE=$OPTARG" )
            ;;
        c|composer)
            args=( "${args[@]}" "--remove-tag=ARTIST" "--set-tag=ARTIST=$OPTARG" "--remove-tag=COMPOSER" "--set-tag=COMPOSER=$OPTARG" )
            ;;
        a|album)
            args=( "${args[@]}" "--remove-tag=ALBUM" "--set-tag=ALBUM=$OPTARG" )
            ;;
        p|performer)
            args=( "${args[@]}" "--remove-tag=PERFORMER" "--set-tag=PERFORMER=$OPTARG" )
            comment="${OPTARG}${comment:+, ${comment}}"
            ;;
        y|year)
            args=( "${args[@]}" "--remove-tag=YEAR" "--set-tag=YEAR=$OPTARG" )
            ;;
        C|comment)
            comment="${comment:+${comment}, }$OPTARG"
            ;;
        r|renumber)
            echo "-r $OPTARG"
            tracknum=$((OPTARG+0))
            ;;
        * )
            echo -e "\n  Option does not exist : '$OPTARG' at position $OPTIND\n"
            EchoUsage
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# 参数个数最少为1
if [[ $# -lt 1 ]] || [[ -z "${#args[@]}" ]]
then
    EchoUsage
    exit 1
fi

if [[ -n "$comment" ]]; then
    args=( "${args[@]}" "--remove-tag=COMMENT" "--set-tag=COMMENT=$comment" )
fi

echo "Tags to be set:"
for i in $(seq 0 $((${#args[*]} - 1))); do
    echo "${args[$i]}" |
        sed -n -e "/^--set-tag=/{s///;p;}"
done

if [[ -z "$DRYRUN" ]]; then
    read -r -p "Confirm to make change? [y/n] " input

    case $input in
        [yY][eE][sS]|[yY])
            echo "Executing..."
            ;;
        [nN][oO]|[nN])
            echo "Aborted"
            exit 2
            ;;
        *)
            echo "Invalid input..."
            exit 3
            ;;
    esac
fi

echo "tracknum=$tracknum"

for f in "$@"; do
    fargs=()
    if [[ -n "$tracknum" ]]; then
        fargs=( "--remove-tag=TRACKNUMBER" "--remove-tag=TRACKTOTAL" "--remove-tag=TRACKTOTALS" "--set-tag=TRACKNUMBER=${tracknum}" )
        tracknum=$((tracknum+1))
    fi

    if [[ "$VERBOSE" == 1* ]] || [[ -n "$DRYRUN" ]]; then
        echo "metaflac ${args[@]} ${fargs[@]} '$f'"
    fi

    if [[ -z "$DRYRUN" ]]; then
        metaflac "${args[@]}" "${fargs[@]}" "$f"
    fi
done

#-c "Pyotr Ilyich Tchaikovsky" -p "André Previn" -C "Lodon Symphony Orchestra" -g "Ballet"
