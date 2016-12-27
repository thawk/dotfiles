function gadd() {
    git add $(git status -s|percol|awk '{print $2}')
}

function gcheckout() {
    git checkout $(git branch|percol)
}

function gpush() {
    git push "$((git remote 2> /dev/null) | percol --auto-match --auto-fail)" "$@"
}

function gpull() {
    git push "$((git remote 2> /dev/null) | percol --auto-match --auto-fail)" "$@"
}

function gfetch() {
    git fetch "$((git remote 2> /dev/null) | percol --auto-match --auto-fail)" "$@"
}

function gitlogcommit() {
    git log --pretty=format:'%h - %s(%cr)'|percol
}

function gitdiffr() {
    git diff -r $(gitlogcommit|awk '{print $1}') $(gitlogcommit|awk '{print $1}') $@
}

