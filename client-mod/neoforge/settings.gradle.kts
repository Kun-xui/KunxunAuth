// NeoForge 模块同样是独立构建。理由见 README：
// ModDevGradle 和 Fabric Loom / ForgeGradle 的插件仓库、Gradle 版本敏感度互不相同，
// 合成一个多模块工程只会让一个插件的失败连坐另外两个。

pluginManagement {
    repositories {
        // ModDevGradle 与 NeoForge 的产物都发布在这里
        maven("https://maven.neoforged.net/releases") { name = "NeoForged" }
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "kunxunauth-device-neoforge"
