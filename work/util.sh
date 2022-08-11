fix_checksum()
{
    if [ $# -eq 0 ]
    then    # 从stdin读取
        sed -e 's/\s/\n/g' |
        awk '
        /\<[0-9a-fA-F]{2}\>/ {
            sum = (sum + strtonum("0x"$0)) % 256
        }
        END {
            printf "%03d\n", sum
        }'
    else    # 从命令行读取
        echo "$@" | gen_checksum
    fi
}
