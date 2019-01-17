export PATH="$HOME/.pyenv/bin:$PATH"
export PYENV_VIRTUALENV_DISABLE_PROMPT=1
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# setup neovim pyenv
[[ -x "$HOME/.pyenv/versions/neovim2/bin/python" ]] && export PYTHON_HOST_PROG="$HOME/.pyenv/versions/neovim2/bin/python"
[[ -x "$HOME/.pyenv/versions/neovim3/bin/python" ]] && export PYTHON3_HOST_PROG="$HOME/.pyenv/versions/neovim3/bin/python"

