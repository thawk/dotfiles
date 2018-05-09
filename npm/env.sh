NPM_BIN="$(npm bin)"
if [ -d "${NPM_BIN}" ]
then
    export PATH=$PATH:${NPM_BIN}
fi
