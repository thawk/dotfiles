# 项目说明

dotfiles 仓库，通过 bootstrap.sh 把 `*.symlink` 文件符号链接到 `$HOME` 对应位置。
`links.txt`（仓库根目录）和 `~/.cache/dotfiles/links.txt` 记录已链接的文件清单。

## 符号链接机制（bootstrap.sh）

- 只链接 `*.symlink` 文件（`find -H ... -name '*.symlink'`），**不链接目录**。
- `create_symlinks`：目标路径为 `$TARGET/${link#*/}`，去掉 `.symlink` 后缀，例如
  `tmux/.tmux/tmux-plugins.conf.symlink` -> `~/.tmux/tmux-plugins.conf`。
- 若目标已存在但不是指向仓库的链接，会交互询问 skip/overwrite/backup。

## subtrees.txt（git subtree 管理）

格式为每行三列：`prefix url branch`，例如：
`fasd/src https://github.com/clvv/fasd.git master`

- `bootstrap.sh -u|update` 会遍历 subtrees.txt，对每行执行
  `git subtree pull --squash --prefix ${prefix} ${url} ${branch}`。
- `#` 开头的行被忽略。
- 新增 subtree 时用 `git subtree add --squash --prefix <prefix> <url> <branch>`，
  并在 subtrees.txt 追加对应行，方便后续统一更新。

## tmux 结构

- `tmux/.tmux.conf.symlink` 和 `tmux/.tmux/*.symlink` 链接到 `~/.tmux.conf` 和 `~/.tmux/`。
- `~/.tmux` 是真实目录（不是符号链接），内含指向 `tmux/.tmux/*.symlink` 的链接，
  以及真实目录 `~/.tmux/plugins/`（tpm 安装插件的位置）。
- `~/.tmux.conf` 中按版本号用 `version-cmp.sh ge/lt` 判断后 source
  `~/.tmux/tmux-plugins.conf`（>= 1.9）或 `~/.tmux/tmux-fallback.conf`（< 1.9）。

### tmux 插件（tmux-plugins.conf.symlink）

- `TMUX_PLUGIN_MANAGER_PATH` 默认 `$HOME/.tmux/plugins/`，插件通过 tpm 安装。
- 启用中的插件：
  - `tmux-plugins/tpm`（loader，文件末尾 `run '~/.tmux/plugins/tpm/tpm'`）
  - `tmux-plugins/tmux-sensible`
  - `christoomey/vim-tmux-navigator`
  - `tmux-plugins/tmux-prefix-highlight`
  - `tmux-plugins/tmux-yank`
  - `tmux-plugins/tmux-sessionist`
  - `tmux-plugins/tmux-pain-control`
  - `tmux-plugins/tmux-cpu`
  - `tmux-plugins/tmux-fpp`（条件：`type fpp` 存在时）
  - `tmux-plugins/tmux-logging`
- conf 中注释掉（当前不启用）的插件：tmux-copycat、tmux-resurrect、tmux-continuum、tmux-open。
- 插件 URL 规则：`tmux-plugins/xxx` -> `https://github.com/tmux-plugins/xxx.git`，
  `christoomey/vim-tmux-navigator` -> `https://github.com/christoomey/vim-tmux-navigator.git`。

