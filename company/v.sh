#!/usr/bin/env bash

S=v
P=/mnt/e/local/vpn
CFG="$P/home.ovpn"
RP=172.31.0.252 # 远端 SOCKS5 代理地址
RP_PORT=10808   # 远端 SOCKS5 端口
LP_PORT=10808   # 本机暴露端口(WSL 内, Windows 用 localhost 访问)
GIT_SERVER=172.31.0.72
GIT_PORT=22
SSH_LP_PORT=10022
cd "$P"

cmd="${1:-vpn}"

go_to_session() {
  if [[ -n "$TMUX" ]]; then
    tmux switch-client -t "$S"
  else
    tmux attach -t "$S"
  fi
}

run_vpn() {
  sudo openvpn --config "$CFG"
}

run_socat() {
  echo "socat"
  exec socat TCP-LISTEN:"$LP_PORT",fork,reuseaddr TCP:"$RP:$RP_PORT"
}

run_git() {
  echo "git forward"
  exec socat TCP-LISTEN:"$SSH_LP_PORT",fork,reuseaddr TCP:"$GIT_SERVER:$GIT_PORT"
}

if [[ -n "$TMUX" ]] && [[ "$(tmux display-message -p '#S')" == "$S" ]]; then
  case "$cmd" in
  vpn) run_vpn ;;
  socat) run_socat ;;
  git) run_git ;;
  *)
    echo "unknown cmd: $cmd"
    exit 1
    ;;
  esac
  exit $?
fi

if tmux has-session -t "$S" 2>/dev/null; then
  echo "tmux session '$S' already exists, switching..."
  go_to_session
  exit $?
fi

tmux new-session -d -s "$S" "$HOME/bin/v.sh vpn"
tmux new-window -d -t "$S" "$HOME/bin/v.sh socat"
tmux new-window -d -t "$S" "$HOME/bin/v.sh git"
tmux select-window -t "$S:0"
echo "started in tmux session '$S', switching..."
go_to_session
