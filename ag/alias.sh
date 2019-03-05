# 如果有vim则用vim。否则用vi。在有vim时，如果没有vi，将vi定义为vim的alias
alias ag='ag --color-match 31\;31 --color-line-number 0\;33 --color-path 0\;32'
# 支持源代码
alias agc='ag --cc --cpp --python --java --vim --go --ruby'
# 忽略第三方代码和测试代码
alias agg='agc --ignore 3rd --ignore unittest --ignore testtool'
# 忽略第三方及库代码
alias ags='agg --ignore lib'
