# KunxunAuth Device —— Minecraft 26.2 多加载器客户端模组

KunxunAuth 服务端插件的配套客户端。它做的事情只有一件：

> 收到服务器的随机挑战 → 用本机 Ed25519 私钥签名 → 把公钥和签名回传。

服务器验签通过就能免密放行；验签不过或者玩家根本没装模组，就退回正常的密码登录。
**装了没装都能进服**，这点是刻意的——客户端模组永远不该成为玩家进不了门的理由。

协议细节见 [PROTOCOL.md](./PROTOCOL.md)（写给服务端插件实现者）。

---

## 目录结构

```
client-mod/
├── PROTOCOL.md                 线格式文档（服务端实现者看这个）
├── README.md                   本文件
├── build-all.ps1               一键依次构建三个加载器
├── common/                     三个加载器共用的纯 Java 代码，不含任何 Minecraft 引用
│   └── src/main/java/top/kunxun/device/
│       ├── DeviceProtocol.java      协议的编解码 + 数据结构
│       ├── DeviceKeyStore.java      私钥文件（加密 properties）读写 + 按账号分文件
│       ├── DeviceIdentity.java      密钥生成/加载 + 签名
│       └── DeviceFingerprint.java   本机硬件指纹（CPU/主板/磁盘/MachineGuid 摘要）
├── fabric/                     Fabric 模块（独立 Gradle 工程）
├── neoforge/                   NeoForge 模块（独立 Gradle 工程）
├── forge/                      Forge 模块（独立 Gradle 工程）
└── dist/                       构建产物（KunxunAuth-Device-1.1.0-<loader>.jar）
```

`common/` **不是**一个 Gradle 子模块，它就是三个源码目录，被各个加载器的
`sourceSets.main.java.srcDirs` 直接挂进去编译。这样做是有原因的：

- 这三个类不引用任何 Minecraft 类，所以**不需要经过 Loom / ModDevGradle 的 remap**；
- 如果做成独立子模块，在 Loom 里要额外配置 `remapJar` 的依赖关系，
  在 ModDevGradle 里又是另一套写法，两边都容易出错；
- 挂进源码目录以后，「Fabric 版签名算法」和「NeoForge 版签名算法」在字节码层面
  是同一份 `javac` 输出，从根上杜绝三端行为不一致。

---

## 环境要求

| 项目 | 版本 | 说明 |
| --- | --- | --- |
| JDK | **25** | MC 26.2 运行在 Java 25 上；模组字节码必须是 25 |
| JDK（仅 Forge 需要） | **8** | ForgeGradle 的 `modifyAccess` 步骤硬性要求 JDK 8，没有会自动下载 |
| Gradle | **9.5.1** | 三个模块各自带 wrapper，也可以自己装 Gradle 9.5.1 |
| 磁盘 | ≥ 4 GB 空闲 | 每个加载器的 Minecraft 依赖 + 反混淆映射加起来约 1 GB |

设好 `JAVA_HOME` 指向 JDK 25 即可，构建脚本用 `toolchain` 声明 Java 25，
Gradle 会优先复用当前运行的 JVM。

> 注意：**运行 Gradle 的 JVM 版本和构建产物要用的 JVM 版本是两件事**。
> Fabric 和 NeoForge 这边，Gradle 9.5.1 直接跑在 JDK 25 上就行；
> Forge 那边 ForgeGradle 7 只要求 Gradle ≥ 9.3，同样可以直接跑在 JDK 25 上。

```powershell
$env:JAVA_HOME = "C:\path\to\jdk-25"
```

---

## 构建

三个模块是**三个互相独立的 Gradle 工程**（各自有自己的 `settings.gradle.kts`）。
不是多模块工程，这是有意的：

> Fabric Loom、ModDevGradle、ForgeGradle 三者的插件仓库和 Gradle 版本敏感度差别很大。
> 如果合成一个多模块工程，Gradle 在配置阶段会无条件加载**全部**子工程的插件，
> 任何一个插件解析失败都会让另外两个一起构建不了。
> 拆开以后「Fabric 成功、Forge 卡住」互不影响，至少能交出一份可用产物。

### 一键构建

```powershell
cd client-mod
.\build-all.ps1
```

产物会被复制到 `client-mod/dist/`。

### 单独构建

```powershell
# Fabric
cd client-mod\fabric
.\gradlew build

# NeoForge
cd client-mod\neoforge
.\gradlew build

# Forge（首次会反编译 Minecraft，很慢，见下文）
cd client-mod\forge
.\gradlew build
```

### 第一次构建会很久

第一次跑任何一个模块，Gradle 都要：

1. 下载 Minecraft 26.2 的客户端 jar 和全部依赖库；
2. 下载并解压反混淆映射（26.2 用的是官方 Mojang 映射）；
3. 把 Minecraft 反混淆成可读的 jar，再把你的模组 remap 回运行时命名。

Fabric / NeoForge 通常 5–15 分钟能完成。

**Forge 还会额外多两件事**，第一次构建前请先知道：

1. ForgeGradle 的 mavenizer 在 `modifyAccess` 这一步**必须有一个 JDK 8**。
   本机没装的话它会自己去 Adoptium 下载 Temurin 8（约 106 MB）并解压到
   Gradle 用户目录的缓存里。如果你的网络需要代理，这一步很容易失败，
   见下面「代理环境下的坑」。
2. 之后才有 `decompile` → `patch` → `recompile` 一长串任务。

在**已经预热好的**机器上（MC 依赖和 JDK 8 都已在缓存里）实测：
Fabric 数秒、NeoForge 约 3 秒、Forge 约 5 分 11 秒。
冷启动第一次会慢得多，具体取决于网速。

### 代理环境下的坑

需要走 HTTP 代理的机器上，有两处**互相独立**的代理配置，只配一处是不够的：

1. **Gradle 自己**（拉插件和依赖）不读 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量，
   要在 Gradle 用户目录的 `gradle.properties` 里写 `systemProp.*`：

   ```properties
   systemProp.http.proxyHost=127.0.0.1
   systemProp.http.proxyPort=27897
   systemProp.https.proxyHost=127.0.0.1
   systemProp.https.proxyPort=27897
   systemProp.http.nonProxyHosts=localhost|127.0.0.1|[::1]
   ```

   症状：拉 `maven.neoforged.net` 时抛
   `SSLHandshakeException: Remote host terminated the handshake`。

2. **ForgeGradle 下载 JDK 8 的子进程**用的是 JDK 自带的 `HttpClient`，
   它只认 JVM 的系统属性，不认上面那份 `systemProp`。所以还要在启动 Gradle
   的 shell 里设 `JAVA_TOOL_OPTIONS`，让每个被 fork 出来的 JVM 都带上：

   ```powershell
   $env:JAVA_TOOL_OPTIONS = '-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=27897 -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=27897 -Dhttp.nonProxyHosts=localhost|127.0.0.1'
   ```

   症状：Forge 构建报 `Failed to find JDK for version 8`，往上翻能看到
   `Failed to download OpenJDK8U-jdk_x64_windows_hotspot_8u504b01.zip
   from https://github.com/adoptium/temurin8-binaries/...`。

---

## 安装

产物在 `client-mod/dist/`：

| 加载器 | 文件 |
| --- | --- |
| Fabric | `KunxunAuth-Device-1.1.0-fabric.jar` |
| NeoForge | `KunxunAuth-Device-1.1.0-neoforge.jar` |
| Forge | `KunxunAuth-Device-1.1.0-forge.jar` |

**按你客户端用的加载器装一个，不要装多个。** 装两个会让同一个挑战被签名两次，
服务端收到两遍 `response`（第二遍因为 nonce 已作废而失败），除了在日志里刷错误没有别的作用。

- **Fabric**：把 jar 丢进 `.minecraft/mods/`，同时确认装了
  [Fabric Loader 0.19.3+](https://fabricmc.net/use/installer/) 和
  [Fabric API 0.160.0+26.2](https://modrinth.com/mod/fabric-api)。
  模组声明了 `"environment": "client"`，装在服务端不会有任何反应。
- **NeoForge**：把 jar 丢进 `.minecraft/mods/`。NeoForge 版本需 ≥ 26.2.0.87。
- **Forge**：把 jar 丢进 `.minecraft/mods/`。Forge 版本需 ≥ 26.2-65.1.3。

首次启动会在游戏目录下生成 `kunxun-device/<账号>-<摘要>.properties`（**一个账号一份**，同一台电脑上的不同账号互不干扰）。**这个文件就是你的设备凭据**，不要分享、不要截图、不要提交到 Git 仓库。

文件里的私钥是加密的，密钥由本机硬件指纹派生（CPU / 主板 / 系统盘 / 机器 ID）。所以：

- 把文件复制到另一台机器 → 解不开 → 客户端自动生成一把新密钥 → 需要重新绑定一次。**复制文件换不来免密**。
- 换了主板 / 重装系统 → 同样是重新绑定一次。要做的事永远只有一件：用密码登录一次，然后在弹出的框里点「绑定这台设备」。

从 1.0.0 升级上来时，旧的 `kunxun-device.properties`（全机共用一份）会被自动改名为 `kunxun-device.properties.legacy-bak`，每个账号各自重新绑定一次即可。

---

## 各加载器实现说明

三个模块解决的是同一个问题：**在配置阶段收发自定义负载**。API 完全不同，
所以每个模块有一份自己的网络封装类，但线格式（PROTOCOL.md）和 `common/` 里的
协议实现是共享的。

### Fabric

- 插件：`fabric-loom` 1.17.20（Fabric 没有发布裸的 `1.17`，只有 1.17.x 补丁号）
- 映射：**`loom.officialMojangMappings()`**。26.2 **没有 Yarn 映射**，只有官方映射可用。
  跟着来的改名要自己认，最典型的是 `ResourceLocation` → `net.minecraft.resources.Identifier`。
- 配置阶段网络 API：
  - 注册：`PayloadTypeRegistry.clientboundConfiguration()` / `.serverboundConfiguration()`
  - 收发：`ClientConfigurationNetworking.registerGlobalReceiver` / `.send` / `.canSend`
  - 负载接口：`CustomPacketPayload`
  - 配置阶段的 `StreamCodec` 参数是 `FriendlyByteBuf`，
    **不是** `RegistryFriendlyByteBuf`（后者只在 play 阶段用）

### NeoForge

- 插件：ModDevGradle 2.x（`net.neoforged.moddev`）
- 版本：NeoForge 26.2.0.87
- 配置阶段网络 API：
  - 注册：`RegisterPayloadHandlersEvent` → `PayloadRegistrar#configurationToClient` / `configurationToServer`
  - 客户端处理器：`RegisterClientPayloadHandlersEvent`
  - ⚠️ **不存在 `RegisterClientConfigurationTasksEvent` 这个类**，别被过时的教程带偏

### Forge

- 插件：ForgeGradle **7.x**（`id 'net.minecraftforge.gradle' version '[7.0.17,8)'`）
- 版本：Forge 26.2-65.1.3
- **ForgeGradle 7 要求 Gradle ≥ 9.3**，而且它和 ForgeGradle 6 的 API 完全不兼容。
  网上（以及老版本 MDK）看到的 `minecraft { mappings ... }` +
  `minecraft "net.minecraftforge:forge:..."` 那套写法是 6.x 的，在 7.x 下会直接
  在配置阶段抛 NPE。7.x 的正确写法是：

  ```groovy
  repositories {
      minecraft.mavenizer(it)   // 把 Forge 的 userdev 产物挂成本地仓库
      maven fg.forgeMaven
      maven fg.minecraftLibsMaven
  }
  dependencies {
      implementation minecraft.dependency('net.minecraftforge:forge:26.2-65.1.3')
  }
  ```

  **26.2 没有 mappings 配置项了**——MC 客户端 jar 本身就是未混淆的，
  mavenizer 的日志里会打印 `Using Mappings: official-26.2` 和
  `srg2names[official-26.2][Empty]`，这是正常的。
- API：`ChannelBuilder` / `SimpleChannel`，配置阶段走
  `SimpleConnection#configuration()` → `SimpleFlow#add` / `addMain`，
  负载类**不实现 `CustomPacketPayload`**——Forge 的 SimpleChannel 靠注册顺序
  区分包，不像 Fabric/NeoForge 那样靠 `Type` 里的 `Identifier`。
- 构建提示：ForgeGradle 对 Gradle / JDK 版本很敏感。如果报
  `Found Gradle version ... Versions Gradle 9.0 and newer are not supported yet`，
  那是拿到 ForgeGradle 6 了，把插件版本改成 `[7.0.17,8)`；
  如果报 `Failed to find JDK for version 8`，见下面「代理环境下的坑」。

---

## 关于 OptiFine

**OptiFine 没有 26.2 版本，所以本项目不提供 OptiFine 模块。**

OptiFine 的更新长期滞后于 Minecraft 正式版，而且它和 Fabric/NeoForge 混装时
还需要 OptiFabric 之类的兼容层。26.2 上目前不存在可用的 OptiFine，
真要提供「OptiFine 版」也无从测试——写一个编译不过也没法运行的模块没有意义。

如果你的玩家群体里有人在用 OptiFine，请让他改用 **Sodium + Iris**（Fabric）或
**Embeddium + Oculus**（Forge/NeoForge），这些在 26.2 上都有可用版本，
而且和本模组不冲突。

---

## 排查

| 现象 | 原因 |
| --- | --- |
| 进服后仍然要求输密码 | 模组没装 / 装错加载器 / 服务端没在配置阶段发挑战。看客户端日志里有没有 `[KunxunAuth]` 开头的行 |
| 同一台电脑上第二个账号绑不上设备 | 模组还是 1.0.0。那版全机共用一把密钥，服务端公钥是全局唯一的，第二个账号必然撞冲突；升到 1.1.0+ 后每个账号各有一把 |
| 升级后提示要重新绑定 | 正常。旧的全机共用密钥已归档成 `.legacy-bak`，每个账号各绑一次 |
| 日志刷 `协议版本不匹配` | 服务端插件和模组的应答版本不一致，对照 PROTOCOL.md 的 `version` 字段（挑战侧恒为 `1`，老模组不会被踢） |
| 日志刷 `负载字段数不对` | 服务端拼字符串时某个字段里混进了 `\|`，检查 playerName |
| 换了电脑 / 换了主板 | 正常。私钥用本机硬件指纹加密，指纹变了就解不开，会自动生成新密钥，重新绑定一次即可 |
| 日志里出现「读不到 CPU / 主板 / 磁盘等硬件标识」 | 系统不允许读硬件信息（精简版系统、受限容器等）。此时指纹只能由主机名拼出来，绑定关系会明显变弱，但不影响免密本身可用 |
