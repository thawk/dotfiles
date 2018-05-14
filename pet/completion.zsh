GOPATH=$(go env GOPATH)

if [ -d "${GOPATH}/src/github.com/knqyf263/pet/misc/completions/zsh" ]
then
    fpath=($fpath "${GOPATH}/src/github.com/knqyf263/pet/misc/completions/zsh")
fi
