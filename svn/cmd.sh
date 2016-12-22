#!/bin/bash
# vim: set ft=sh fenc=utf-8:
#
# Rainer Müller <raimue@codingfarm.de>
# Version 2012-02-09
# http://raim.codingfarm.de/blog/2012/02/09/subversion-diff-with-vimdiff-improved
#
# Released into Public Domain

# Extended svn diff functionality
if [ -n "$(which svn 2>/dev/null)" ]; then
    function svn() {
        local svn=$(type -fp svn)
        case "$1" in
            diff-plain)
                shift;
                echo "$@"
                $svn diff --diff-cmd diff "$@"
                ;;
            diff-color)
                shift;
                $svn diff --diff-cmd colordiff "$@"
                ;;
            diff-vim)
                shift;

                local file=""
                local rev="-rBASE"

                while [ $# -gt 0 ]; do
                    case "$1" in
                        --)
                            break;
                            ;;
                        -r*)
                            rev="$1"
                            if [ "$1" == "-r" ]; then
                                shift
                                rev="-r$1"
                            fi
                            ;;
                        --revision)
                            shift
                            rev="-r$1"
                            ;;
                        -*)
                            echo "svn: invalid option: $1"
                            return 1
                            ;;
                        *)
                            if [ -n "$file" ]; then
                                echo "svn: diff-vim works with one single filename only" >&2
                                return 1
                            fi
                            file="$1"
                            ;;
                    esac
                    shift;
                done;

                local tmp=$(mktemp -t svn-diff-vim.XXXXXXXXXX || return 1).${file##*.}
                $svn cat $rev "$file" > $tmp || return 1
                chmod a-w $tmp || return 1
                vimdiff "$file" $tmp || return 1
                rm -f $tmp || return 1
                ;;
            diff-filemerge)
                shift;
                $svn diff --diff-cmd $HOME/libexec/svndiff -x opendiff "$@"
                ;;
            diff-less)
                shift;
                $svn diff --diff-cmd colordiff "$@" |less -FRX
                ;;
            pc|propcopy)
                if [ $# -lt 4 ]; then
                    echo "svn: Not enough arguments provided" >&2
                    return 1
                fi
                propName=$2
                fromFile=$3
                shift 3
                $svn propset $propName "$($svn propget $propName $fromFile)" "$@"
                ;;
            *)
                $svn "$@"
                ;;
        esac
    }
fi
