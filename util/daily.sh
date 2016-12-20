#!/usr/bin/env sh

# Start of day. Bring over new stuffs
sod()
{
    date +'%Y-%m-%d %H:%M:%S'
    if which task > /dev/null
    then
        task sync
    fi

    for repo in ~/.timewarrior ~/.vim ~/.dotfiles
    do
        if [ -d "${repo}" ]
        then
            echo "--= Pulling ${repo}... =--"
            pushd "${repo}" > /dev/null
            git pull
            popd > /dev/null
        fi
    done
}

# End of day. Commit works
eod()
{
    date +'%Y-%m-%d %H:%M:%S'
    if which task > /dev/null
    then
        task sync
    fi

    for repo in ~/.timewarrior
    do
        if [ -d "${repo}" ]
        then
            echo "--= Commiting ${repo}... =--"
            pushd "${repo}" > /dev/null
            git add -u && git commit -m "Commit at $(date +'%Y-%m-%d %H:%M:%S') on ${HOSTNAME}"
            git push
            popd > /dev/null
        fi
    done
}
