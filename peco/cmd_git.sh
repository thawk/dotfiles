function gadd() {
    # shellcheck disable=SC2046
    git add $(git status -s|peco|awk '{print "$2"}')
}

function gcheckout() {
    git checkout "$(git branch|peco)"
}

function gpush() {
    git push "$( (git remote 2> /dev/null) | peco --auto-match --auto-fail)" "$@"
}

function gpull() {
    git push "$( (git remote 2> /dev/null) | peco --auto-match --auto-fail)" "$@"
}

function gfetch() {
    git fetch "$( (git remote 2> /dev/null) | peco --auto-match --auto-fail)" "$@"
}

function gitlogcommit() {
    git log --pretty=format:'%h - %s(%cr)'|peco
}

function gitdiffr() {
    git diff -r "$(gitlogcommit|awk '{print $1}')" "$(gitlogcommit|awk '{print $1}')" "$@"
}

