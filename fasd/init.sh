fasd_cache_dir="${HOME}/.cache/fasd"
[ ! -d "${fasd_cache_dir}" ] && mkdir -p "${fasd_cache_dir}"

fasd_cache="${fasd_cache_dir}/fasd-init-cache"
if [ "$(command -v fasd)" -nt "$fasd_cache" -o ! -s "$fasd_cache" ]; then
    fasd --init auto >| "$fasd_cache"
fi

source "$fasd_cache"
unset fasd_cache
unset fasd_cache_dir

alias v="fasd -f -e $EDITOR"
# alias o='fasd -a -e open_command'
