PREFIX   ?= /usr
BIN_DIR   = /bin
COLOR_DIR = /share/dynamic-colors/colorschemes
BASH_DIR  = /share/bash-completion/completions
ZSH_DIR   = /share/zsh/site-packages

.PHONY: build install

build:
	@echo "No building required..."

install:
	@mkdir -p $(PREFIX)$(BASH_DIR) $(PREFIX)$(ZSH_DIR)
	@install -Dm755 -t $(PREFIX)$(BIN_DIR)   bin/dynamic-colors           
	@install -Dm644 -t $(PREFIX)$(COLOR_DIR) colorschemes/*               
	@install -Dm644 completions/*.bash $(PREFIX)$(BASH_DIR)/dynamic-colors
	@install -Dm644 completions/*.zsh  $(PREFIX)$(ZSH_DIR)/_dynamic-colors
