#if [ -n "$(python -c 'import site; print(site.USER_SITE)')" ]
#then
#    export PYTHONPATH=$(python -c "import site; print(site.USER_SITE)"):$PYTHONPATH
#fi
