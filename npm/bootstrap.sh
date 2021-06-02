env_file="${DOTFILES_LOCAL}/npm/env.sh"
mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*

NPM_ROOT="$(npm root -g)"
if [ -d "${NPM_ROOT}" ]
then
    : > "${env_file}"
    echo "export NODE_PATH=${NPM_ROOT}" >> "${env_file}"
fi
