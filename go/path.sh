GOPATH=$(go env GOPATH)
if [ -d "${GOPATH}/bin" ]
then
    export PATH=$PATH:${GOPATH}/bin
fi
