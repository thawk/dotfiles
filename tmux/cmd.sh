# # 打开指定名称的session
# tm() {
#     first_session="$1"
#
#     while [ ! -z "$1" ]
#     do
#         [ -z "$first_session" ] && first_session="$1"
#         tmxu has-session -t "$1" 2> /dev/null
#         if [ $? != 0 ]
#         then
#             tmux new -d -s "$1"
#         fi
#         shift
#     done
#
#     if [ ! -z "$first_session" ]
#     then
#         tmux attach -t "$first_session"
#     fi
# }

