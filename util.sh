init_local_config() {
    local plug_name="$1"
    local conf_path="${DOTFILES_LOCAL}/${plug_name}"
    if [[ -n "${plug_name}" ]]; then
        [[ -d "${conf_path}" ]] && rm -r "${conf_path}"
        mkdir -p "${conf_path}"
        echo "${conf_path}"
    else
        echo "${DOTFILES_LOCAL}/not_exists"
    fi
}

