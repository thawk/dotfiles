#!/usr/bin/env bash

pull_repos() {
    for repo in "$@"; do
        if [ -d "${repo}" ]
        then
            echo "-= Pulling ${repo}... =-"
            cd "${repo}" || continue
	    git pull --recurse-submodules --rebase
            echo
        fi
    done
}

if ping 172.31.0.72 -n 1 | grep TTL; then
    echo "Private Git Server is REACHABLE"
    pull_repos /e/my/{keepass,config,doc,pkm,work,party,reference,fonts} /e/local/thunderbird/szse.profile/Mail
else
    echo "Private Git Server is NOT reachable"
fi

pull_repos /e/my/{private_work,scores,study,wiki,presentations} "$HOME"/{.SpaceVim,.SpaceVim.d}

#music
