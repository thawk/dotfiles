# init_plugin "plugin_name"
# env_file="$(create_plugin_file env.sh)"
#
get_dotfiles_local_dir() {
    echo "${XDG_CACHE_HOME:-$HOME/.cache}/dotfiles"
}

get_config_dir() {
    local plugin_name="${1:-$PLUGIN_NAME}"
    local dotfiles_local
    dotfiles_local="$(get_dotfiles_local_dir)"
    echo "${dotfiles_local}/${plugin_name:-not_exists}"
}

init_plugin() {
    PLUGIN_NAME="$1"
    local config_dir
    config_dir="$(get_config_dir "$PLUGIN_NAME")"

    mkdir -p "${config_dir}"
    rm -f "${config_dir}"/*
}

create_plugin_file() {
    local config_name="$1"
    local config_file
    config_file="$(get_config_dir)/$config_name"
    : > "${config_file}"
    echo "${config_file}"
}
