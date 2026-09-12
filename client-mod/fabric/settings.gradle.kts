// Fabric 模块是**独立构建**（自己一个 Gradle 根工程），不和其他加载器共用 settings。
// 原因：Fabric Loom / ModDevGradle / ForgeGradle 三个插件放在同一个多模块工程里时，
// Gradle 会无条件地配置所有子工程——任何一个插件解析失败都会连带把另外两个拖垮，
// 而三者的插件仓库、Gradle 版本敏感度完全不同。拆开以后「Fabric 能过、Forge 卡住」
// 是互不影响的，交付时至少有一份可用产物。

pluginManagement {
    repositories {
        // fabric-loom 的插件标记只发布在 Fabric 自己的 maven 上
        maven("https://maven.fabricmc.net/") { name = "Fabric" }
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "kunxunauth-device-fabric"
