fasd_cache_dir="${HOME}/.cache/fasd"
[ ! -d "${fasd_cache_dir}" ] && mkdir -p "${fasd_cache_dir}"

fasd_cache="${fasd_cache_dir}/fasd-init-${SHELL##*/}"
if [ "$(command -v fasd)" -nt "$fasd_cache" -o ! -s "$fasd_cache" ]; then
    if [ "\$ZSH_VERSION" ] && compctl; then # zsh
        fasd --init posix-alias zsh-hook zsh-ccomp zsh-ccomp-install zsh-wcomp zsh-wcomp-install >| "$fasd_cache"
    elif [ "\$BASH_VERSION" ] && complete; then # bash
        fasd --init posix-alias bash-hook bash-ccomp bash-ccomp-install >| "$fasd_cache"
    else # posix shell
        fasd --init posix-alias posix-hook >| "$fasd_cache"
    fi
fi

source "$fasd_cache"
unset fasd_cache
unset fasd_cache_dir
