# dotfiles

自用的``Linux``/``MacOS``/``cygwin``/``MSYS2``配置文件。

参考了[holman](https://github.com/holman/dotfiles)的配置。

> 本配置库不含``vim``/``neovim``配置。可以在[这里](https://github.com/thawk/dotspacevim)找到我对应[SpaceVim](https://spacevim.org)配置，在[这里](https://github.com/thawk/dotvim)可以找到我以前手工维护的``vim``配置，可根据自己的需要自行选用，也可以配合其他``vim``/``neovim``配置使用。

## 文件组织

文件按软件/用途分目录存放，把同一用途的文件组织在一起，方便管理。

在每个子目录下有以下特殊文件和目录：

. **disabled**: 如存在，禁用此目录。这个不是提交到git库，只在本地生效
. **disabled.global**: 如存在，禁用此目录。这个会提交到git库，其他机器也会禁用此目录
- **requirements.sh**: 如存在，则必须有可执行权限。在安装（``bootstrap.sh``）时，根据此脚本的返回结果决定是否启用本子目录。可用于判断目录所依赖的命令是否存在
- **bin/**: bin目录会被加入$PATH以便随时可用
- **\*.sh**: 子目录下的``*.sh``（不含子目录）会被source进当前环境。``*.bash``/``*.zsh``只会被``bash``/``zsh``载入
    - **bootstrap.sh**/**bootstrap**: 必须可执行，将在运行``bootstrap.sh``，本目录从未启用变成启用时执行
    - **path.sh**: 子目录下的``path.sh``会先于其它脚本source进环境，可以在这个脚本中设置``$PATH``
    - **env.sh**: 会在``path.sh``之后，其他脚本之前加载，可用于export环境变量
    - **completion.sh**/**completion\_*.sh**: 子目录下的``completion.sh``会被最后载入，可以在这个脚本中设置自动补全
    - 其它脚本可以随意命名，但有一些建议
        - **aliases.sh**: 可用于设置alias
        - **bindkey.sh**: 可用于设置key binding
        - **config.sh**: 可用于设置一些配置，如使用``setopt``
        - **functions.sh**: 可用于保存一些function
- **\*.symlink**: 所有以``.symlink``结尾在文件或目录会被符号链接到``$HOME``
- **zsh-completion**: 本目录将加入``$fpath``中，可用于存放zsh的补全脚本

对于``zsh``，**path.sh**和**env.sh**会在插件载入前加载，其他脚本则会在插件载入后再进行加载。

## 安装

```sh
git clone https://github.com/thawk/dotfiles.git ~/.dotfiles
~/.dotfiles/bootstrap.sh
```

由于在``.zshrc``中在``$0``不是``~/.zshrc``，无法确定``.dotfiles``目录的位置，所以在``zsh``/``.zshrc.symlink``和``bash``/``.bashrc.symlink``中都显式指定``.dotfiles``的位置，因此只能clone到``~/.dotfiles``。

使用``zi``管理zsh的插件。可以编辑``~/.dotfiles/zsh/scripts/zi.plugins.zsh``管理插件。

一些运行时产生的中间文件会存放到``$XDG_CACHE_HOME/dotfiles``（一般在``~/.cache/dotfiles/``）下，因此也可以删除并重建``~/.dotfiles``以进行升级。

升级后应再次运行``~/.dotfiles/bootstrap.sh``以更新插件配置，更新符号连接等。

如果需要支持**aarch64**，需要从 `https://github.com/romkatv/gitstatus/releases` 下载相应可执行程序，放到 ``~/.cache/gitstatus/`` 目录下。

**tmux**插件需要在tmux中，按`<C-A>I`进行安装，安装后会自动重启tmux。

## 配置

### 运行时配置

在每次运行时，会载入一些额外的配置文件，以便用户可以进行订制：

* **~/.localrc**: 会在``.bashrc``/``.zshrc``中载入
* **~/.bashrc.local**: 会在``.bashrc``中载入
* **~/.zshrc.local**: 会在``.zshrc``中载入

> k 这几个配置文件会在``zsh``载入插件前载入。
> - 在顶层shell中（``$SHLVL`` == ``1``），会以``top``为参数被调用，以便进行启动``gpg-agent``之类等动作，因此可以根据``$1``是否等于``top``判断是否顶层shell
> - 在普通shell中，``$1``为空

### 调整配置的环境变量

除了各个插件或系统自带的选项外，还可以设置下列以``DOTFILES_``开头的本配置专用的变量:

* ``DOTFILES_THEME``：控制使用的配色方案

  可选值为：
  
  | 取值      | 含义|
  |-----------|---------------------------------------------------------------------------------------------------------------------------------|
  | solarized | 自动载入上次的``solarized``配色，在``mintty``等支持``ANSI``转义的终端下，可用``dynamic-colors``命令实时切换亮色和暗色。         |
  | base16    | 自动载入上次的``base16``配色，在``mintty``等支持``ANSI``转义的终端下，可用``base16_*``命令实时切换不同的配色。但不支持``putty`` |
  | 空串      | 自动载入上次的``dynamic-colors配色``                                                                                            |
  | 其他      | 不自动载入配色                                                                                                                  |

  > 会根据使用配色，对一些插件的颜色进行修正。

* ``DOTFILES_SRC_ROOT``: 代码库的根。如``$HOME/workspace``
* ``MY_SOCKS5_PROXY``: 设置SOCK5代理的地址和端口，用于``ap``和``setproxy``。缺省为``127.0.0.1:1080``
* ``MY_HTTP_PROXY``: 设置HTTP代理的地址和端口，用于``ap``和``setproxy``。缺省为空。如不为空，会设置`http_proxy`和`https_proxy`
* ``DOTFILES_ENV``: 运行环境。部分功能只在特定环境提供。缺省为`inet`环境，表示互联网

## 暴露环境变量

* ``DOTFILES_ROOT``: dotfiles目录，一般为`$HOME/.dotfiles`
* ``DOTFILES_LOCAL``: dotfiles本地配置目录，一般为`$HOME/.cache/dotfiles`
