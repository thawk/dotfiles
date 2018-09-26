GOPATH=$(go env GOPATH)
[ -z "$GOPATH" ] && export GOPATH=${HOME}/go
[ -z "$GOROOT" ] && export GOROOT=$(go env GOROOT)

if [ -d "${GOROOT}/bin" ]
then
    export PATH=$PATH:${GOROOT}/bin
fi

if [ "${GOPATH}" != "${GOROOT}" ] && [ -d "${GOPATH}/bin" ]
then
    export PATH=$PATH:${GOPATH}/bin
fi
