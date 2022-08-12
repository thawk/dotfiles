#!/usr/bin/env bash
function complete_remote_paths() {
    word_to_complete=${COMP_WORDS[COMP_CWORD]}
    command_line=${COMP_LINE}

    # If the command line contains ^/ we should start completing
    if [[ "$command_line" ==  *^/* ]]; then
        # Create a base path for svn to use which only contains complete folder
        # names. Examples:
        # ^/bra => ^/
        # ^/branches/foo = ^/branches/
        basepath=$(echo "${word_to_complete}"|sed -re 's#[^/]+$##')

        # Generate a list of words to complete the command.
        COMPREPLY=($(compgen -W "$(get_remote_paths)" -- "${word_to_complete}"))
    fi
}

function get_remote_paths() {
    # List all remote paths at given base path. Prepend the basepath to all
    # lines from svn ls in order to work with compgen.
    svn ls "${basepath}" 2>/dev/null | sed -e 's#^#'"$basepath"'#'
}

# Add completion for svn command, use function for completing and don't add any
# extra whitespaces at the end of remote path.
complete -o nospace -o plusdirs -F complete_remote_paths svn
