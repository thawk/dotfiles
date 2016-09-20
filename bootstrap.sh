#!/usr/bin/env bash
#
# bootstrap installs things.

DOTFILES_ROOT="$(dirname "$(readlink -f "$0")")"

set -e

info () {
    printf "\r  [ \033[00;34m..\033[0m ] $1\n"
}

user () {
    printf "\r  [ \033[0;33m??\033[0m ] $1\n"
}

success () {
    printf "\r\033[2K  [ \033[00;32mOK\033[0m ] $1\n"
}

fail () {
    printf "\r\033[2K  [\033[0;31mFAIL\033[0m] $1\n"
    echo ''
    exit
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
            success "removed $dst"
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
            success "skipped $src"
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
        success "linked $1 to $2"
    fi
}

install_dotfiles () {
    info 'installing dotfiles'

    local overwrite_all=false backup_all=false skip_all=false

    for src in $(find -H "$DOTFILES_ROOT" -name '*.symlink' -not -path '*.git')
    do
        rel=$(realpath --relative-to "$DOTFILES_ROOT" "$src")
        dst="$TARGET/${rel#*/}"
        dst="${dst%.symlink}"
        link_file "$src" "$dst"
    done
}

function EchoUsage()
{
    echo "
Usage: $(basename "$0") [options]

  Options:
      -h [ --help ]                show this screen
      --apply                      apply modify instead of print it
      -t [ --target=<TARGET_DIR> ] target directory, defaults to \$HOME
" >&2
}

TEMP=$(getopt -o h,t: --long help,apply,target: -- "$@")

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

# Note the quotes around `$TEMP': they are essential!
eval set -- "$TEMP"

DRY_RUN=yes
TARGET=$HOME

while true ; do
    case "$1" in
        -h|--help)
            EchoUsage
            exit 1
            ;;
        --apply)
            DRY_RUN=no
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

setup_gitconfig
install_dotfiles

echo ''
echo '  All installed!'
