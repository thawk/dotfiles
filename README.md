# dotfiles

自用的Linux/cygwin/MSYS2配置文件。

参考了 [holman](https://github.com/holman/dotfiles) 的配置。

## 文件组织

文件按软件/用途分目录存放，把同一用途的文件组织在一起，方便管理。

在每个子目录下有以下特殊文件和目录：

- **bin/**: bin目录会被加入$PATH以便随时可用
- **\*.sh**: 子目录下的\*.sh（不含子目录）会被source进当前环境。\*.bash/\*.zsh只会被bash/zsh载入
    - **path.sh**: 子目录下的path.sh会先于其它脚本source进环境，可以在这个脚本中设置$PATH
    - **completion.sh**/**completion_\*.sh**: 子目录下的completion.sh会被最后载入，可以在这个脚本中设置自动补全
    - 其它脚本可以随意命名，但有一些建议
        - **env.sh**: 可用于export环境变量
        - **aliases.sh**: 可用于设置alias
        - **config.sh**: 可用于设置一些配置，如使用setopt
        - **functions.sh**: 可用于保存一些function
- **\*.symlink**: 所有以.symlink结尾在文件或目录会被符号链接到$HOME

## 本地配置文件

一些含有私有信息的文件将不会放入github中，而是单独存放：

- **~/.localrc**: 会在.bashrc/.zshrc中载入
- **~/.bashrc.local**: 会在.bashrc中载入
- **~/.zshrc.local**: 会在.zshrc中载入
- **~/.gitconfig.local**: 包含git用户名，会在.gitconfig中载入

## 安装

```sh
git clone https://github.com/thawk/dotfiles.git ~/.dotfiles
cd ~/.dotfiles
./bootstrap
```

由于在.zshrc中在$0不是~/.zshrc，无法确定dotfiles目录在位置，所以在zsh/.zshrc.symlink和bash/.bashrc.symlink中都显式指定dotfiles的位置，因此只能clone到~/.dotfiles

如果使用zsh，建议clone oh-my-zsh：

```sh
git clone https://github.com/robbyrussell/oh-my-zsh.git ~/.oh-my-zsh
```
