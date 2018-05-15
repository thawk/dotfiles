GOPATH=$(go env GOPATH)
[ -z "$GOPATH" ] && export GOPATH=${HOME}/go

if [ -d "${GOPATH}/bin" ]
then
    export PATH=$PATH:${GOPATH}/bin
fi
