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

get_dotfiles_local_dir() {
    echo "${XDG_CACHE_HOME:-$HOME/.cache}/dotfiles"
}

get_config_dir() {
    local plugin_name="$1"
    local dotfiles_local="$(get_dotfiles_local_dir)"
    echo "${dotfiles_local}/${plugin_name}"
}

init_config_dir() {
    local plugin_name="$1"
    local config_dir="$(get_config_dir "$plugin_name")"

    mkdir -p "${config_dir}"
    rm -f "${config_dir}"/*
}

init_config_file() {
    local plugin_name="$1"
    local config_name="$2"
    local config_file="$(get_config_dir "$plugin_name")/$config_name"
    : > "${config_file}"
    echo "${config_file}"
}
