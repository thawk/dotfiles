env_file="${DOTFILES_LOCAL}/java/env.sh"
mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*

java_home=/usr/libexec/java_home
if [ -x "$java_home" ]; then
    JAVA_HOME="$($java_home)"
    if [ -d "${JAVA_HOME}" ]
    then
        : > "${env_file}"
        echo "export JAVA_HOME=${JAVA_HOME}" >> "${env_file}"
    fi
fi
