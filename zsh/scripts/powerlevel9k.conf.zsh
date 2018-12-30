#DEFAULT_USER=$USER

POWERLEVEL9K_MODE="nerdfont-complete"

POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(os_icon dir vcs)
POWERLEVEL9K_RIGHT_PROMPT_ELEMENTS=(status root_indicator background_jobs context time ssh)
POWERLEVEL9K_PROMPT_ON_NEWLINE=true
POWERLEVEL9K_RPROMPT_ON_NEWLINE=false
POWERLEVEL9K_MULTILINE_FIRST_PROMPT_PREFIX=""

local user_symbol="$"
if [[ $(print -P "%#") =~ "#" ]]; then
    user_symbol = "#"
fi

POWERLEVEL9K_CONTEXT_TEMPLATE="%n@`hostname -s`"
#POWERLEVEL9K_CONTEXT_TEMPLATE="\U1f4BB%n@`hostname -s`"

POWERLEVEL9K_PROMPT_ADD_NEWLINE=true

#POWERLEVEL9K_MULTILINE_FIRST_PROMPT_PREFIX="╭"
#POWERLEVEL9K_MULTILINE_LAST_PROMPT_PREFIX="%{%B%F{yellow}%K{blue}%} $user_symbol%{%b%f%k%F{blue}%} %{%f%}"
#POWERLEVEL9K_MULTILINE_LAST_PROMPT_PREFIX="╰ %{%B%F{black}%K{blue}%} $user_symbol %{%b%f%k%F{blue}%} %{%f%}"
#POWERLEVEL9K_MULTILINE_LAST_PROMPT_PREFIX="╰ $user_symbol "
POWERLEVEL9K_MULTILINE_FIRST_PROMPT_PREFIX="%{%K{black}%}\u256D\u2500%{%k%}"
#POWERLEVEL9K_MULTILINE_LAST_PROMPT_PREFIX="%{%K{black}%}\u2570\uf460 $user_symbol %{%F{black}%k%}%{%f%k%}"
POWERLEVEL9K_MULTILINE_LAST_PROMPT_PREFIX="%{%K{black}%}\u2570\uf460%{%F{black}%k%}%{%f%k%}"

POWERLEVEL9K_SHOW_CHANGESET=false
POWERLEVEL9K_CHANGESET_HASH_LENGTH=6
#POWERLEVEL9K_TIME_FORMAT="%D{%F %T}"
POWERLEVEL9K_TIME_FORMAT="\uf017 %D{%H:%M:%S}"
POWERLEVEL9K_TIME_ICON=""

POWERLEVEL9K_VCS_GIT_GITHUB_ICON=""
POWERLEVEL9K_VCS_GIT_BITBUCKET_ICON=""
POWERLEVEL9K_VCS_GIT_GITLAB_ICON=""
POWERLEVEL9K_VCS_GIT_ICON=""

