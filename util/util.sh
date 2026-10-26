ansiesc() {
  sed -e 's/\[[0-9;]\+m//g'
}

vman() {
  vim +"set ft=man" +"Man $*"
}

setproxy() {
  # 如果命令行没有提供代理地址，使用MY_SOCKS5_PROXY的值，如果也没有设置就用127.0.0.1:1080
  local proxy=${1:-${MY_SOCKS5_PROXY:-127.0.0.1:1080}}
  # Detect netcat executable
  local netcat=
  if type netcat &>/dev/null; then
    netcat=netcat
  elif type nc &>/dev/null; then
    netcat=nc
  fi

  export all_proxy=socks5h://${proxy}
  export ALL_PROXY=socks5h://${proxy}

  if [[ -n "$netcat" ]]; then
    export GIT_SSH_COMMAND="ssh -o ProxyCommand=\"${netcat} -x ${proxy} %h %p\""
  fi
}

resetproxy() {
  export all_proxy=
  export GIT_SSH_COMMAND=
}

cdd() {
  if type tmux &>/dev/null; then
    # 如果当前tmux session名称正好是$DOTFILES_SRC_ROOT下的目录名，则进入该目录
    local proj_name
    local src_root

    proj_name="$(tmux display-message -p '#S')"
    src_root="${DOTFILES_SRC_ROOT:-$HOME/workspace}"

    if [[ -d "${src_root}/${proj_name}" ]]; then
      cd "${src_root}/${proj_name}" || return
      return
    fi

    if [[ -d "${HOME}/${proj_name}" ]]; then
      cd "${HOME}/${proj_name}" || return
      return
    fi
  fi

  # 没有找到与tmux session名称对应的项目，找当前目录往上的VCS目录作为项目的根目录
  # 如果有多个VCS目录，说明存在一些子项目，取最顶层目录
  local last_proj_root=
  local dir="$PWD"
  local last_dir=

  while [[ "$dir" != "$last_dir" ]]; do
    for d in .git _darcs .hg .bzr .svn; do
      if [[ -e "$dir/$d" ]]; then
        last_proj_root="$dir"
        break
      fi
    done

    last_dir="$dir"
    dir="$(dirname "$dir")"
  done

  if [[ -d "$last_proj_root" ]]; then
    cd "$last_proj_root" || return
  fi
}

alias_expand() {
  if [[ -n "$ZSH_VERSION" ]]; then
    # shellcheck disable=2154  # aliases referenced but not assigned
    [ ${aliases[$1]+x} ] && printf '%s\n' "${aliases[$1]}" && return
  else # bash
    [ "${BASH_ALIASES[$1]+x}" ] && printf '%s\n' "${BASH_ALIASES[$1]}" && return
  fi
  printf '%s\n' "$1"
}

fsed() {
  [[ $# -lt 2 ]] && {
    echo 'usage: fsed <sed cmd> <files>' 2>&1
    return 1
  }
  for file in "${@:2}"; do mv -nv "$file" "$(sed "$1" <<<"$file")"; done
}

mount() {
  command mount | sed -e 's/^\(.*\) on \([^ ]*\)/\1\t\2\t/' | sort -t$'\t' -k2 -f | column -s$'\t' -t
}

resolve_link() {
  $(type -p greadlink readlink | head -1) "$1"
}
