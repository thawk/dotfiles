#!/usr/bin/env bash

. "$DOTFILES_ROOT/logging.sh"

VERBOSE=1

transmission_dir=/mnt/media/downloads/transmission
download_dir=${transmission_dir}/download
incoming_dir=${transmission_dir}/incoming
#target_roots=(/mnt/store/movies /mnt/store/tv /mnt/store/music /mnt/main/media/musics /mnt/main/media/audio_video)
target_roots=(/mnt/store /mnt/main/media)
target_dir=/mnt/store/inbox
file_db=download_filename.txt

EchoUsage()
{
    echo "
Usage: ${0##*/} [options]

    Options:

    -h : Show this screen
    -y : Make real links
    -a : Add new files
    -r : Rename (Will BROKEN transmission)
    -R : Remove
    " >&2
}

TEMP=$(getopt hyarR $*)

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

# Note the quotes around `$TEMP': they are essential!
set -- $TEMP

confirm=
add=
rename=
while true ; do
    case "$1" in
        -h|--help)
            EchoUsage
            exit 1
            ;;
        -y|--confirm)
            confirm=1
            shift 1
            ;;
        -a|--add)
            add=1
            shift 1
            ;;
        -r|--rename)
            rename=1
            shift 1
            ;;
        -R|--remove)
            remove=1
            shift 1
            ;;
        --)
            shift
            break
            ;;
        *) 
            fail "Unexpected option '$1'"
            exit 1
            ;;
    esac
done 

declare -A db
declare -A db_all

debug "Gathering registered filenames..."
while IFS=$'\t' read s t
do
    [ -z "$t" ] && continue

    if [[ "$s" == '#'* ]]; then
        debug "  Adding # '${s:1}' -> '$t'"
        db_all["${s:1}"]="$t"
        db["${s:1}"]="$t"
    else
        debug "  Adding   '$s' -> '$t'"
        db_all["$s"]="$t"
    fi
done << HERE
    $(cat "${file_db}")
HERE

debug "Processing command..."
if [ -n "$add" ]
then
    hori_tab=$(echo -e '\011')
    count=0

    for f in ${download_dir}/* ${incoming_dir}/*
    do
        f=${f##*/}
        [ "${f}" != "*" ] || continue

        debug "  Checking '$f' -> '${db_all[$f]}'"
        if [[ -n "${db_all[$f]}" ]]; then
            continue
        fi

        count=$((count + 1))
        printf "%2s: ${f}\n" ${count}
        read -p "输入中文名（回车跳过）：" name
        if [ "${name}" = "." ]; then
            echo -e "${f}\t${f}" >> "${file_db}"
        elif [ -n "${name}" ]; then
            echo -e "${f}\t${name}.${f}" >> "${file_db}"
        fi
    done

    [ ${count} -le 0 ] && success "Nothing new."
else
    readarray -t links < <(find ${target_roots} -type l)
    declare -A real_links
    for l in "${links[@]}"; do
        real_links["$(readlink "$l")"]="$l"
    done
    
    count=0
    if [ -n "$rename" ]
    then
        target_dir="$download_dir"
    fi

    for f in "${!db[@]}"; do
        source="${download_dir}/$f"
        target="${target_dir}/${db[$f]}"

        [ ! -e "$source" ] && continue

        debug "Checking '$source'"
        if [[ -n "${real_links[$source]}" ]]; then
            debug "  Found '${real_links[$source]}'"
            continue
        fi

        count=$((count + 1))

        if [ -n "$remove" ]
        then
            debug "  rm -r '$source'"
            info "rm -r '$source'"
        else
            if [ -n "$confirm" ]
            then
                if [ -n "$rename" ]
                then 
                    debug "  mv '$source' '$target'"
                    mv "$source" "$target"
                else
                    debug "  ln -s '$source' '$target'"
                    ln -s "$source" "$target"
                fi
                success "  %2s: $target ... Done" $count
            else
                info "  %2s: $target" $count
            fi
        fi
    done

    if [ $count -eq 0 ]
    then
        success "Nothing to do."
    elif [ -z "$confirm" ]
    then
        echo
        success "run '${0##*/} -y' to make links"
    fi
fi

