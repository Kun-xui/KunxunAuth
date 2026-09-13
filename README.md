# KunxunAuth

Paper 26.2 服务端登录插件。玩家在进入世界之前，通过进服对话框完成邮箱验证码注册或密码登录；服务器只需要准备一个能发信的邮箱，整套登录就能跑起来。

客户端模组是可选的。不装模组的玩家走正常的密码登录；装了模组的玩家在这台设备上可以免密进服，体验接近正版账号。

```
Minecraft 26.2 / Java 25 / Paper api-version 26.2
```

---

## 一个邮箱就是全部前提

离线服务器（非正版验证）的传统做法是让玩家注册一个密码，问题是密码可以被猜、被撞库、被同一个玩家注册一堆小号。加邮箱验证能挡住这些，但大多数实现要么依赖额外的验证服务、要么要求玩家装客户端。

这个插件把前提压到最低：搭建服务器的人准备一个邮箱账号并开启 SMTP 服务（例如 QQ 邮箱在设置里生成授权码），把账号和授权码填进 `secret.yml`，登录系统就完整可用了。数据库默认用内嵌 SQLite，零配置；玩家数量上来之后可以在 `config.yml` 里切成 MySQL。插件需要的四个依赖库由 Paper 的 `libraries` 机制在启动时自动下载，不用手动丢 jar。

玩家那边不需要安装任何东西。想免密登录的玩家可以额外装一个客户端模组，不装则完全不受影响。

---

## 玩家看到什么

对话框走的是 Minecraft 1.20.2 之后新增的 configuration 阶段，也就是玩家已经过了身份握手、但还没进入世界的那一段。验证在这里完成，玩家不会先看到「正在登录…」的空场景界面。

| 玩家类型 | 流程 |
| --- | --- |
| 新玩家 | 连接 → 弹注册框 → 填邮箱 → 收验证码 → 填验证码并设置密码 → 进入世界 |
| 已注册玩家 | 连接 → 弹登录框 → 填密码 → 进入世界 |
| 忘记密码 | 弹找回框 → 填邮箱 → 收验证码 → 设置新密码 → 进入世界 |

对话框最长等待 300 秒（`pre-join.timeout-seconds`），超时踢出；默认不允许按 Esc 关闭。这些都可以改。

对于 1.21.6 以前的客户端，配置阶段不存在对话框，插件会按 `pre-join.legacy-client-mode` 处理：

- `chat`（默认）放行进世界，改用 `/register`、`/verify`、`/login` 聊天命令完成验证，期间由冻结保护锁住玩家；
- `kick` 直接踢出并提示升级客户端。

选了 `chat` 时，未验证的玩家会处于冻结状态：无法移动（可以转头）、无法破坏或放置方块、无法与实体或方块交互、无法拾取丢弃或使用物品、无法打开容器、无法攻击或被攻击、无法进传送门、聊天和命令也会被拦下。列表见 `ProtectionListener.java`。

---

## 免密登录

装了客户端模组的玩家，在一次正常的密码登录之后会收到「绑定这台设备」的询问。绑定完成后，从这台设备进服就不再需要密码。

原理是 Ed25519 挑战应答。**每台设备、每个账号各有一把密钥**，私钥写在 `.minecraft/kunxun-device/<账号>-<摘要>.properties`，永不离开这台机器。玩家进服时服务端发一个每次都不一样的随机挑战，客户端用私钥签名回传，服务端拿登记过的公钥验签。协议里不出现密码，也没有任何长期有效的传输凭据。

为什么是「一个账号一把」而不是「一台机器一把」：1.0.0 是后者，后果是同一台电脑上的第二个账号（比如一个正版号加一个离线小号）永远绑不上设备 —— 服务端那边公钥是全局唯一的，第二把绑定请求只会撞上唯一约束。那个账号于是每次登录都得输密码。1.1.0 把密钥按账号分开，两个账号各绑各的，互不干扰。

私钥落盘时是**加密**的，密钥由本机硬件指纹（CPU / 主板 / 系统盘 / 机器 ID 的摘要）派生。把这个文件复制到另一台机器上，AES-GCM 根本解不开，客户端会重新生成一把新密钥并让玩家重新绑定一次 —— 复制文件换不来免密。

这套设计的几个关键点：

- nonce 由 `SecureRandom` 生成，至少 16 字节熵，验证后立刻作废，因此抓包拿到的应答无法重放。Ed25519 是确定性签名，不换 nonce 的话同一组输入签名结果恒定，重放就是致命的。
- 签名原文里包含玩家名，所以即便别人拿到了某台设备的应答包，也只能用来登录那个玩家的账号。
- 服务端验签时用自己记录的玩家名重建签名原文，`response` 包里根本没有玩家名字段，攻击者无从注入。
- 客户端还会上报一个硬件指纹摘要，服务端把它存进设备表。`device.fingerprint-mode` 决定怎么用它：`record`（默认）只记录并告警，`strict` 则在不一致时作废该绑定、要求重新绑定。两种模式都会在作废后允许玩家重新绑定，不会把人挡在门外。
- 每个账号最多绑定 3 台设备（`device.max-devices-per-account`）。上限是必需的：私钥文件本身就是凭据，没有上限的话账号被盗后连「哪些是设备」都说不清。
- 玩家改密码或通过邮箱重置密码后，该账号名下全部设备自动吊销（`device.revoke-on-password-change`）。这是账号被盗后的第一处置动作。
- 玩家可以用 `/kunxundevice list` 查看已绑定设备，用 `/kunxundevice remove <序号>` 删除某一台；管理员用 `/kunxunauth devices <玩家>` 还能看到机器指纹前缀。

**从 1.0.0 升级到 1.1.0**：原来那份全机共用的 `kunxun-device.properties` 会被自动改名为 `kunxun-device.properties.legacy-bak` 保留下来。按账号分密钥之后，服务端认不出原来那把公钥该归哪个账号，所以**每个账号需要各自用密码登录一次并重新绑定**，只做一次。模组和插件请一起升级。

完整的线格式、字段编码规则、跨语言实现注意事项，以及这套协议明确不解决的问题，都在 [client-mod/PROTOCOL.md](client-mod/PROTOCOL.md)。那份文档是写给服务端实现者的，用任意语言、任意服务端平台都能照着实现一遍。

三端模组共用同一份协议与签名代码（`client-mod/common/`，不引用任何 Minecraft 类），从字节码层面杜绝三端行为不一致。

---

## 面向机器人与小号的三层拦阻

注册这道门被三道机制守着，每一道都可以在 `config.yml` 里单独调。

邮箱域名是第一道。默认只放行国内主流邮箱（`qq.com`、`foxmail.com`、`163.com`、`126.com`、`yeah.net`、`sina.com`、`sohu.com`、`21cn.com`、`139.com`、`189.cn`、`wo.cn`、`aliyun.com`），子域名同样算通过。同时另有一份黑名单收着 35 条一次性邮箱域名，作为白名单万一被清空时的第二道保险。

频率与数量是第二道。同一个 IP 每小时最多注册 3 个账号、最多触发 10 次验证码发送，同时最多保持 5 条并发连接。同一个邮箱只能绑定 1 个账号。验证码有效期 10 分钟、最多尝试 5 次、重发间隔 60 秒。

登录侧是第三道。连续输错 5 次锁定账号 10 分钟。密码存储用 PBKDF2-HMAC-SHA256，迭代 210000 次（OWASP 现行建议值）。

---

## 凭据怎么放

`config.yml` 是打进 jar 的默认配置，会被复制、备份、分发，所以任何真实凭据都不应该写在那里。插件按下面的优先级取三层配置：

```
环境变量  >  secret.yml  >  config.yml
```

对应的环境变量名是 `KUNXUN_MAIL_ACCOUNT`、`KUNXUN_MAIL_PASSWORD`、`KUNXUN_MYSQL_PASSWORD`。容器或面板部署用环境变量最省事，普通部署用插件目录下的 `plugins/KunxunAuth/secret.yml`。从这个仓库构建出来的 jar 里，`mail.account` 和 `mail.password` 都是空的，必须在上面两层之一填上，否则插件发不出验证码。

其余几处刻意的设计：

- 管理命令 `/kunxunauth setpassword` 不再接受明文密码参数，改为签发一个 15 分钟有效的一次性重置码，由管理员转交玩家。这样密码不会进服务器日志、RCON 日志和面板历史。
- 管理命令输出里的玩家 IP 默认打码成 `1.2.*.*` 这种形式。
- 验证码明文默认不写日志（`misc.log-verification-codes: false`）。

---

## 部署

服务端需要 Java 25 和 Paper 26.2。

```bash
git clone https://github.com/Kun-xui/KunxunAuth.git
cd KunxunAuth
mvn package
```

产物是 `target/KunxunAuth-1.1.0.jar`，丢进服务器的 `plugins/` 目录。

启动一次服务器，插件会生成 `plugins/KunxunAuth/config.yml` 和 `secret.yml`。停服，编辑 `secret.yml`：

```yaml
mail:
  account: 'your-account@qq.com'
  password: '你的邮箱授权码'
```

授权码不是邮箱登录密码。QQ 邮箱的获取路径是「设置 → 账号 → POP3/SMTP 服务」，开启后生成一串授权码。再启动服务器，登录系统即可工作。

`config.yml` 里其它常用的开关：`register.allow-registration` 控制是否开放注册，`mail.enable` 控制是否发信，`pre-join.enable` 控制是否使用对话框流程，`device.fingerprint-mode` 控制硬件指纹是只记录（`record`）还是强制校验（`strict`），`misc.welcome-message` 是验证通过后的欢迎语。

---

## 命令与权限

| 命令 | 别名 | 说明 |
| --- | --- | --- |
| `/register <邮箱>` | `/reg` | 通过聊天注册，旧版本客户端使用 |
| `/verify <验证码> <密码>` | `/code` | 提交邮箱验证码，用于注册和找回密码 |
| `/login <密码>` | `/l` | 通过聊天登录，旧版本客户端使用 |
| `/resetpassword <邮箱>` | `/forgot`、`/resetpw` | 通过邮箱验证码找回密码 |
| `/kunxundevice <list\|remove 序号>` | `/kadevice`、`/kadev` | 管理自己的设备绑定 |
| `/kunxunauth <help\|reload\|stats\|info\|unregister\|restore\|setpassword\|unlock\|devices\|revokeall>` | `/kauth`、`/ka` | 管理命令 |

| 权限 | 默认 | 说明 |
| --- | --- | --- |
| `kunxunauth.admin` | op | 使用管理命令 |
| `kunxunauth.bypass` | false | 跳过登录检查 |
| `kunxunauth.device` | true | 使用 `/kunxundevice` 管理自己的设备绑定 |

插件与 ViaVersion 兼容（`softdepend`），装了 ViaVersion 时会按客户端真实协议号判断能不能显示对话框。

---

## 从源码构建客户端模组

客户端模组是三个互相独立的 Gradle 工程，不是多模块工程。Fabric Loom、ModDevGradle、ForgeGradle 三者的插件仓库和 Gradle 版本敏感度差别很大，合成一个多模块工程的话，任何一个插件解析失败都会让另外两个一起构建不了。

需要 JDK 25，Forge 模块还额外需要 JDK 8（ForgeGradle 的 `modifyAccess` 步骤硬性要求，本机没有的话它会自己下载）。

```powershell
cd client-mod
.\build-all.ps1
```

产物复制到 `client-mod/dist/`。三个模块各自也带 wrapper，可以单独构建。首次构建需要下载 Minecraft 客户端 jar 和反混淆映射，Fabric 与 NeoForge 大致 5 到 15 分钟，Forge 还要经历反编译和重编译，更久。网络需要走代理时有两处独立的代理配置，具体见 [client-mod/README.md](client-mod/README.md)。

| 加载器 | 产物 | 客户端版本要求 |
| --- | --- | --- |
| Fabric | `KunxunAuth-Device-1.1.0-fabric.jar` | Fabric Loader 0.19.3+ 与 Fabric API 0.160.0+26.2 |
| NeoForge | `KunxunAuth-Device-1.1.0-neoforge.jar` | NeoForge 26.2.0.87+ |
| Forge | `KunxunAuth-Device-1.1.0-forge.jar` | Forge 26.2-65.1.3+ |

三个文件按客户端使用的加载器选一个安装，同时装两个会让同一个挑战被签名两次，除了刷错误日志没有别的作用。完整安装说明见 [client-mod/dist/安装说明.txt](client-mod/dist/安装说明.txt)。

模组声明了 `"environment": "client"`，装在服务端不会有任何反应。它不含任何游戏资源，不修改游戏内容，对帧数和存档没有影响。

---

## 目录结构

```
KunxunAuth/
├── pom.xml                     服务端插件（Maven）
├── src/main/java/com/kunxun/auth/
│   ├── command/                玩家命令与管理命令
│   ├── config/                 配置读取、消息、凭据分层
│   ├── data/                   账号模型与数据访问（SQLite / MySQL）
│   ├── device/                 设备免密登录服务端实现
│   ├── dialog/                 进服对话框的构建与回调
│   ├── listener/               未验证玩家的行为封锁
│   ├── mail/                   SMTP 发信
│   ├── session/                会话、流程编排、冻结服务
│   └── util/                   邮箱校验、密码哈希、限流、验证码
└── client-mod/                 免密登录客户端模组
    ├── common/                 三端共用的协议与签名实现
    ├── fabric/                 Fabric 模块
    ├── neoforge/               NeoForge 模块
    ├── forge/                  Forge 模块
    └── dist/                   构建产物与安装说明
```

构建缓存目录（`.gradle/`）、`target/`、`build/` 以及 Minecraft 客户端 jar 和反混淆映射都已被 `.gitignore` 排除，不进仓库。它们体积以 GB 计，而且重新分发 Minecraft 二进制违反 Mojang EULA。

---

## 已知限制

免密登录建立在「私钥文件只在这台机器上有意义」这个前提上，而这一点靠的是**硬件指纹加密**：文件被复制到别处就解不开。这条防线有一个明确的边界 —— 指纹里的字段（CPU 型号、主板序列号、磁盘序列号、机器 ID）都是本机任何程序都读得到的公开信息，所以在同一台机器上跑一个伪造指纹的程序，仍然可以把私钥解出来。要做到「文件复制到任何地方都无效」，需要 TPM 这类硬件密钥库，不在本项目的范围内。

换主板、换系统盘、重装系统、虚拟机快照还原都可能让指纹变化，表现就是免密失效、需要重新绑定一次。这是设计取舍：宁可在硬件变动时多要一次密码，也不要让一份被复制走的文件长期有效。

客户端模组跑在玩家机器上，玩家可以拿改过的客户端签任何东西。签名证明的是「私钥持有者」，不是「客户端未被修改」。真正确认玩家身份仍然依赖首次绑定时的那一次密码登录。同理，`device.fingerprint-mode: strict` 拦得住「换了机器」这种正常情况，拦不住一个刻意伪造指纹的客户端 —— 那种情况靠客户端侧的加密兜底，而不是靠服务端比对。

26.2 上没有可用的 OptiFine，所以本项目不提供 OptiFine 模块。如果玩家群体里有人在用 OptiFine，建议改用 Sodium 加 Iris（Fabric）或 Embeddium 加 Oculus（Forge / NeoForge），这些在 26.2 上都有可用版本，且与本模组不冲突。

---

## 排查

| 现象 | 原因 |
| --- | --- |
| 进服后仍然要求输密码 | 模组没装、装错加载器，或服务端没在配置阶段发挑战。看客户端日志里有没有 `[KunxunAuth]` 开头的行 |
| 同一台电脑上第二个账号绑不上设备 | 客户端模组还是 1.0.0。那版全机共用一把密钥，服务端公钥又是全局唯一的，第二个账号必然撞冲突。升到 1.1.0+ 后每个账号各有一把，各绑一次即可 |
| 升级后提示要重新绑定 | 正常。旧的 `kunxun-device.properties` 已归档成 `.legacy-bak`，按账号分密钥后每个账号都要重新绑一次 |
| 换了主板 / 重装系统后不再免密 | 正常。设备密钥是用硬件指纹加密的，指纹一变就解不开，客户端会生成新密钥并重新绑定 |
| 发不出验证码 | `secret.yml` 里的 `mail.account` 或 `mail.password` 没填，或邮箱未开启 SMTP 服务 |
| 日志刷「协议版本不匹配」 | 服务端插件和模组的应答版本不一致，对照 `PROTOCOL.md` 的 `version` 字段。挑战那一侧一直用 `1`，所以老模组不会因此被踢 |
| 日志刷「负载字段数不对」 | 服务端拼字符串时某个字段里混进了 `\|` |
| 换了电脑要重新绑定 | 正常。密钥跟着账号和机器走，新机器就是新设备 |
| 点「取消」后要等一下才断开 | 1.1.0 已修：取消时先停掉设备挑战与补发、关掉对话框，再发断开提示 |

---

## 许可证

MIT License，见 [LICENSE](LICENSE)。可以自由使用、修改和再分发，包括用于商业服务器。
