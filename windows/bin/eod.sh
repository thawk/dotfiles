#!/usr/bin/env bash

commit_repos() {
    for repo in "$@"; do
        if [ -d "${repo}" ]
        then
            echo "-= Commiting ${repo}... =-"
            cd "${repo}"
            git add -A && git commit -m " Auto commit at $(date +'%Y-%m-%d %H:%M:%S') on ${HOSTNAME}"
            git diff --exit-code origin/master &> /dev/null || git push
            echo
        fi
    done
}

if ping 172.31.0.72 -n 1 | grep TTL; then
    echo "Private Git Server is REACHABLE"
    commit_repos /e/my/{keepass,config,doc,pkm,work,party,reference,fonts} /e/local/thunderbird/szse.profile/Mail
else
    echo "Private Git Server is NOT reachable"
fi

commit_repos /e/my/{private_work,scores,study,wiki,presentations} "$HOME/.SpaceVim.d"

#music
