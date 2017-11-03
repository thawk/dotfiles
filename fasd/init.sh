fasd_cache_dir="${HOME}/.cache/fasd"
[ ! -d "${fasd_cache_dir}" ] && mkdir -p "${fasd_cache_dir}"

fasd_shell="${SHELL##*/}"
fasd_cache="${fasd_cache_dir}/fasd-init-${fasd_shell}"
if [ "$(command -v fasd)" -nt "$fasd_cache" -o ! -s "$fasd_cache" ]; then
    if [ "$fasd_shell" == "zsh" ]; then # zsh
        fasd --init posix-alias zsh-hook zsh-ccomp zsh-ccomp-install zsh-wcomp zsh-wcomp-install >| "$fasd_cache"
    elif [ "$fasd_shell" == "bash" ]; then # bash
        fasd --init posix-alias bash-hook bash-ccomp bash-ccomp-install >| "$fasd_cache"
    else # posix shell
        fasd --init posix-alias posix-hook >| "$fasd_cache"
    fi
fi

source "$fasd_cache"
unset fasd_shell
unset fasd_cache
unset fasd_cache_dir
