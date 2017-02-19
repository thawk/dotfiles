#!/usr/bin/env bash
#
# bootstrap installs things.

DOTFILES_ROOT="$(dirname "$(readlink -f "$0")")"

set -e

debug () {
    # printf "\r  [ \033[00;34m..\033[0m ] $1\n" > /dev/stderr
    echo > /dev/null
}

info () {
    printf "\r  [ \033[00;34m..\033[0m ] $1\n" > /dev/stderr
}

user () {
    printf "\r  [ \033[0;33m??\033[0m ] $1\n" > /dev/stderr
}

success () {
    printf "\r\033[2K  [ \033[00;32mOK\033[0m ] $1\n" > /dev/stderr
}

skip () {
    # printf "\r\033[2K  [\033[00;35mSKIP\033[0m] $1\n" > /dev/stderr
    echo > /dev/null
}

fail () {
    printf "\r\033[2K  [\033[0;31mFAIL\033[0m] $1\n" > /dev/stderr
    echo ''
    exit
}

relpath() {
    if type python > /dev/null
    then
        python -c "import os.path; print(os.path.relpath('$1','${2:-$PWD}'))"
    elif type realpath &> /dev/null
    then
        realpath --relative-to="${2:-$PWD}" "$1"
    fi
}

setup_gitconfig () {
    if ! [ -f $DOTFILES_ROOT/git/.gitconfig.local.symlink ]
    then
        info 'setup gitconfig'

        git_credential='cache'
        if [ "$(uname -s)" == "Darwin" ]
        then
            git_credential='osxkeychain'
        fi

        user ' - What is your github author name?'
        read -e git_authorname
        user ' - What is your github author email?'
        read -e git_authoremail

        if [ "${DRY_RUN}" = 'yes' ]
        then
            echo git/.gitconfig.local.symlink
            sed -e "s/AUTHORNAME/$git_authorname/g" -e "s/AUTHOREMAIL/$git_authoremail/g" -e "s/GIT_CREDENTIAL_HELPER/$git_credential/g" $DOTFILES_ROOT/git/.gitconfig.local.symlink.example
        else
            sed -e "s/AUTHORNAME/$git_authorname/g" -e "s/AUTHOREMAIL/$git_authoremail/g" -e "s/GIT_CREDENTIAL_HELPER/$git_credential/g" $DOTFILES_ROOT/git/.gitconfig.local.symlink.example > $DOTFILES_ROOT/git/.gitconfig.local.symlink
        fi

        success 'gitconfig'
    fi
}


setup_taskrc () {
    if ! [ -f $DOTFILES_ROOT/taskwarrior/.taskrc.symlink ]
    then
        info 'setup taskrc'

        if [ "${DRY_RUN}" = 'yes' ]
        then
            echo taskwarrior/.taskrc.symlink
        else
            cp $DOTFILES_ROOT/taskwarrior/.taskrc.symlink.example $DOTFILES_ROOT/taskwarrior/.taskrc.symlink
        fi

        success 'taskrc'
    fi
}


link_file () {
    local src=$1 dst=$2

    local overwrite= backup= skip=
    local action=

    if [ -f "$dst" -o -d "$dst" -o -L "$dst" ]
    then

        if [ "$overwrite_all" == "false" ] && [ "$backup_all" == "false" ] && [ "$skip_all" == "false" ]
        then

            local currentSrc="$(readlink $dst)"

            if [ "$currentSrc" == "$src" ]
            then
                skip=true;
            else
                user "File already exists: $dst ($(basename "$src")), what do you want to do?\n\
                    [s]kip, [S]kip all, [o]verwrite, [O]verwrite all, [b]ackup, [B]ackup all?"
                read -n 1 action

                case "$action" in
                    o )
                        overwrite=true;;
                    O )
                        overwrite_all=true;;
                    b )
                        backup=true;;
                    B )
                        backup_all=true;;
                    s )
                        skip=true;;
                    S )
                        skip_all=true;;
                    * )
                        ;;
                esac
            fi
        fi

        overwrite=${overwrite:-$overwrite_all}
        backup=${backup:-$backup_all}
        skip=${skip:-$skip_all}

        if [ "$overwrite" == "true" ]
        then
            if [ "${DRY_RUN}" = 'yes' ]
            then
                echo "      => rm -rf \"$dst\""
            else
                rm -rf "$dst"
            fi
            success "  removed $dst"
        fi

        if [ "$backup" == "true" ]
        then
            if [ "${DRY_RUN}" = 'yes' ]
            then
                echo "      => mv \"$dst\" \"${dst}.backup\""
            else
                mv "$dst" "${dst}.backup"
            fi
            success "moved $dst to ${dst}.backup"
        fi

        if [ "$skip" == "true" ]
        then
            skip "  skipped $src"
        fi
    fi

    if [ "$skip" != "true" ]  # "false" or empty
    then
        parent=$(dirname "$2")

        if [ ! -d "$parent" ]
        then
            if [ "${DRY_RUN}" = 'yes' ]
            then
                echo "      => mkdir -p \"$parent\""
            else
                mkdir -p "$parent"
            fi
        fi

        if [ "${DRY_RUN}" = 'yes' ]
        then
            echo "      => ln -s \"$1\" \"$2\""
        else
            ln -s "$1" "$2"
        fi
        success "  linked $1 to $2"
    fi

    unset src dst overwrite backup skip action
}

get_symlinks() {
    for dir in "$@"
    do
        for src in $(find -H "$dir" -name '*.symlink' -not -path '*.git')
        do
            rel=$(relpath "$src" "$DOTFILES_ROOT")
            echo "$rel"
        done
    done

    unset dir src
}

create_symlinks () {
    local dir

    for dir in $(get_addtional_paths "$@")
    do
        export PATH=$PATH:$dir
    done

    info 'Creating symbol links...'

    local overwrite_all=false backup_all=false skip_all=false
    local -A links
    
    for link in $(get_symlinks "$@")
    do
        links["$link"]="$link"
    done

    if [ -e "$DOTFILES_ROOT/links.txt" ]
    then
        for link in $( cat "$DOTFILES_ROOT/links.txt" )
        do
            if ! [ "${links["$link"]+isset}" ]
            then
                dst="$TARGET/${link#*/}"
                dst="${dst%.symlink}"

                if [ -e "$dst" ]
                then
                    if [ -h "$dst" -a "$DOTFILES_ROOT/$link" == "$(readlink $dst)" ]
                    then
                        info "  rm outdated \"$dst\""
                        if [ "${DRY_RUN}" = 'yes' ]
                        then
                            echo "      => rm \"$dst\""
                        else
                            rm "$dst"
                        fi
                    else
                        skip "  $dst is not symlink, ignore removing"
                    fi
                else
                    debug "  $dst not exists, no need to remove"
                fi
            fi
        done
    fi

    cat /dev/null > "$DOTFILES_ROOT/links.txt"
    for link in "${links[@]}"
    do
        echo "$link" >> "$DOTFILES_ROOT/links.txt"
        dst="$TARGET/${link#*/}"
        dst="${dst%.symlink}"
        link_file "$DOTFILES_ROOT/$link" "$dst"
    done
}

generate_source_list () {
    shell="$1"

    orig_nullglob=
    shopt nullglob > /dev/null && orig_nullglob=1
    shopt -s nullglob

    typeset -a path_sh env_sh completion_sh others_sh

    while [ $# -gt 1 ]
    do
        shift

        dir=$1
        debug "    Handling scripts in ${dir}..."

        for f in "${dir}"/*.sh "${dir}"/*."${shell}"
        do
            if [[ "${f##*/}" =~ ^path\.[^.]*$ ]]; then
                path_sh[${#path_sh[*]}]="$f"
                debug "      Add $f ito path.sh..."
            elif [[ "${f##*/}" =~ ^env\.[^.]*$ ]]; then
                env_sh[${#env_sh[*]}]="$f"
                debug "      Add $f ito env.sh..."
            elif [[ "${f##*/}" =~ ^completion\.[^.]*$ ]]; then
                completion_sh[${#completion_sh[*]}]="$f"
                debug "      Add $f ito completion.sh..."
            elif ! [[ "${f##*/}" =~ ^requirements\.[^.]*$ ]]; then
                others_sh[${#others_sh[*]}]="$f"
                debug "      Add $f ito others.sh..."
            else
                debug "      Ignoring $f..."
            fi
        done
    done

    # reset nullglob if original value is false
    [ -z "$orig_nullglob" ] && shopt -u nullglob

    echo
    echo "# set paths"
    for f in "${path_sh[@]}"
    do
        echo "source \"$f\""
    done | sort

    echo
    echo "# set environments"
    for f in "${env_sh[@]}"
    do
        echo "source \"$f\""
    done | sort

    echo
    echo "# others scripts"
    for f in "${others_sh[@]}"
    do
        echo "source \"$f\""
    done | sort

    echo
    echo "# completion scripts"
    for f in "${completion_sh[@]}"
    do
        echo "source \"$f\""
    done | sort

    unset f shell path_sh env_sh completion_sh others_sh orig_nullglob
}

function join_by {
    local d=$1
    shift
    echo -n "$1"
    shift
    printf "%s" "${@/#/$d}"
}

get_enabled_dir() {
    info "Checking disabled directory..."
    for dir in $(find "$DOTFILES_ROOT" -maxdepth 1 -type d ! -name '.*' | sort)
    do
        if [ -f "${dir}/requirements.sh" ] && ! "${dir}/requirements.sh"
        then
            info "  Disable ${dir}"
            continue
        fi

        debug "  Enable ${dir}"
        echo ${dir}

    done

    unset dir
}

get_addtional_paths() {
    local dir=

    for dir in "$@"
    do
        [ -d "${dir}/bin" ] && echo "${dir}/bin"
    done
}

generate_script_file() {
    local dir= shell= script_name=

    for shell in bash zsh
    do
        script_name=script.${shell}
        info "Generating ${script_name} for ${shell}"

        cat /dev/null > "$script_name"

        echo -n "export PATH=\$PATH" >> "$script_name"

        for dir in $(get_addtional_paths "$@")
        do
            echo -n ":${dir}" >> "$script_name"
        done
        echo >> "$script_name"
        generate_source_list $shell "$@" >> "$script_name"
    done
}

function EchoUsage()
{
    echo "
Usage: $(basename "$0") [options]

  Options:
      -h [ --help ]                show this screen
      --dry-run                    print modify instead of apply it
      -t [ --target=<TARGET_DIR> ] target directory, defaults to \$HOME
" >&2
}

TEMP=$(getopt -o h,t: --long help,apply,target: -- "$@")

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

# Note the quotes around `$TEMP': they are essential!
eval set -- "$TEMP"

DRY_RUN=no
TARGET=$HOME

while true ; do
    case "$1" in
        -h|--help)
            EchoUsage
            exit 1
            ;;
        --dry-run)
            DRY_RUN=yes
            shift 1
            ;;
        -t|--target)
            TARGET=$2
            shift 2
            ;;
        --)
            shift 1
            break
            ;;
        *)
            echo "Unknown parameter '$1'!"
            exit 1
            ;;
    esac
done

echo ''

if [ "${DRY_RUN}" = 'yes' ]
then
    echo "!!! DRY RUN !!!"
    echo ''
else
    echo "!!! Apply mode !!!"
    echo ''
fi

typeset -a dirs

dirs=( $(get_enabled_dir) )

setup_gitconfig
setup_taskrc
generate_script_file "${dirs[@]}"
create_symlinks "${dirs[@]}"

unset dirs

echo ''
echo '  All installed!'
