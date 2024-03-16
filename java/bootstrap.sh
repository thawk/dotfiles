#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "java"
env_file="$(create_plugin_file env.sh)"

java_home=/usr/libexec/java_home
if [ -x "$java_home" ]; then
    JAVA_HOME="$($java_home)"
    if [ -d "${JAVA_HOME}" ]
    then
        : > "${env_file}"
        echo "export JAVA_HOME=${JAVA_HOME}" >> "${env_file}"
    fi
fi
