for cmd in asciidoctor asciidoctor-pdf asciidoctor-epub3
do
    if ! type ${cmd} &> /dev/null ; then
        alias ${cmd}="docker run -it --rm -v \$(pwd):/documents/ asciidoctor/docker-asciidoctor ${cmd} -r asciidoctor-diagram"
    fi
done
