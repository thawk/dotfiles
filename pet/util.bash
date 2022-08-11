function prev() {
    PREV=$(fc -lrn | head -n 1)
    sh -c "pet new $(printf %q "$PREV")"
}

function pet-select() {
  BUFFER=$(pet search --query "$READLINE_LINE")
  READLINE_LINE=$BUFFER
  READLINE_POINT=${#BUFFER}
}
bind -x '"\C-x\C-r": pet-select'
