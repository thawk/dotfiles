#!/usr/bin/env bash

SRC_FILE=${1:-dotfiles.tar.bz2}

success () {
    printf "\r\033[2K  [ \033[00;32mOK\033[0m ] $1\n" > /dev/stderr
}

info () {
    printf "\r  [ \033[00;34m..\033[0m ] $1\n" > /dev/stderr
}

fail () {
    printf "\r\033[2K  [\033[0;31mFAIL\033[0m] $1\n" > /dev/stderr
    echo ''
    exit 1
}

if [ ! -e "${SRC_FILE}" ]
then
    fail "'${SRC_FILE}' not existed, aborted!"
fi

info "Backing up..."

for dir in .dotfiles .vim .tmux
do
    if [ -e "${HOME}/${dir}" ]
    then
        if [ -e "${HOME}/${dir}.old" ]
        then
            # only remove old backup while new backup is needed
            info "  Removing outdated '${HOME}/${dir}.old'..."
            rm -rf "${HOME}/${dir}.old" || fail "    Failed to remove '${HOME}/${dir}'"
        fi

        info "  Backing up '${HOME}/${dir}'..."
        mv "${HOME}/${dir}" "${HOME}/${dir}.old" || fail "    Failed to backup '${HOME}/${dir}'"
    fi
done

info "Extracting '${SRC_FILE}'..."
tar -C "${HOME}" -xvf "${SRC_FILE}"

info "Setting up new configurations..."
info "  Setting up .dotfiles..."
"${HOME}/.dotfiles/bootstrap.sh" || fail "    Failed executing '${HOME}/.dotfiles/bootstrap.sh'"

info "  Setting up .vim..."
"${HOME}/.vim/bootstrap.sh" || fail "    Failed executing '${HOME}/.vim/bootstrap.sh'"

success "Done."
