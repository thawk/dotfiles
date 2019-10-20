# vim:ft=zsh:fdm=marker

# Options
# Save each command's beginning timestamp
#setopt extended_history
# Older commands that duplicate newer ones are omitted
setopt hist_save_no_dups
# Lock history file using system fcntl call, vs. ad-hoc file locking
setopt hist_fcntl_lock
# Do not find dupes when searching history in line editor
setopt hist_find_no_dups
setopt noshare_history

# Parameters
# Do not *write* the following commands to environment command history
HISTORY_IGNORE="(?|??|cd|cd [~-.]|cd ..|tmux|vim|declare|env|alias|exit|history *|pwd|clear|jobs|mount|brew up*|brew cleanup|em *|um|um *|vim */private/*|vim private/*|cd private|cd private/*)"
#HISTORY_IGNORE="(l[alsh]#( *)#|cd|pwd|exit|cd ..|em *|um|um *)"

zshaddhistory() {
	emulate -L zsh
	## uncomment if HISTORY_IGNORE
	## should use EXTENDED_GLOB syntax
	setopt extendedglob
	[[ $1 != ${~HISTORY_IGNORE} ]]
}
