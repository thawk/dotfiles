#!/usr/bin/env bash

EchoUsage()
{
    echo "
Usage: $(basename "$0") [options] [--] <flac files>

    Options:
        -h|help            Display this message
        -v|verbose         Display more verbose log
        -g|genre <val>     Set GENRE tag
        -c|composer <val>  Set ARTIST/COMPOSER tag
        -a|album <val>     Set ALBUM tag
        -p|performer <val> Set PERFORMER tag
        -C|comment <val>   Set COMMENT tag
" >&2
}

VERBOSE=
args=
comment=

while getopts ":hvg:c:a:p:C:" opt; do
    case $opt in
        h|help)
            EchoUsage
            exit 0
            ;;
        v|verbose)
            VERBOSE="${VERBOSE}1"
            ;;
        g|genre)
            args="${args} --remove-tag=GENRE --set-tag=\"GENRE=$OPTARG\""
            ;;
        c|composer)
            args="${args} --remove-tag=ARTIST --set-tag=\"ARTIST=$OPTARG\" --remove-tag=COMPOSER --set-tag=\"COMPOSER=$OPTARG\""
            ;;
        a|album)
            args="${args} --remove-tag=ALBUM --set-tag=\"ALBUM=$OPTARG\""
            ;;
        p|performer)
            args="${args} --remove-tag=PERFORMER --set-tag=\"PERFORMER=$OPTARG\""
            comment="${OPTARG}${comment:+, ${comment}}"
            echo "$opt $OPTARG comment=$comment"
            ;;
        C|comment)
            comment="${comment:+${comment}, }$OPTARG"
            echo "$opt $OPTARG comment=$comment"
            ;;
        * )
            echo -e "\n  Option does not exist : '$OPTARG' at position $OPTIND\n"
            EchoUsage
            exit 1
            ;;
    esac
done
shift $(($OPTIND-1))

# 参数个数最少为1
if [[ $# -lt 1 ]] || [[ -z "$args" ]]
then
    EchoUsage
    exit 1
fi

if [[ -n "$comment" ]]; then
    args="${args} --remove-tag=COMMENT --set-tag=\"COMMENT=$comment\""
fi

echo "Tags to be set:"
echo "$args" |
    sed 's/ --remove-tag=[A-Za-z0-9]*//g' |
    sed "s/ --set-tag='/\n/g" |
    sed "s/'\$//"

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

metaflac "$args" "$@"

#-c "Pyotr Ilyich Tchaikovsky" -p "André Previn" -C "Lodon Symphony Orchestra" -g "Ballet"
