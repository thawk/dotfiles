env_file="${DOTFILES_LOCAL}/devtoolset/env.sh"
mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*

echo 'for d in $(ls -d /opt/rh/llvm-toolset-* | sort -Vr); do
    if [[ -e "$d/enable" ]]; then
        . "$d/enable"
        break
    fi
done' >> "${env_file}"

echo 'for d in $(ls -d /opt/rh/devtoolset-* | sort -Vr); do
    if [[ -e "$d/enable" ]]; then
        . "$d/enable"
        break
    fi
done' >> "${env_file}"
