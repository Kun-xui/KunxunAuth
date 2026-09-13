// ---------------------------------------------------------------------------
// KunxunAuth Device —— Fabric 26.2 客户端模组
// ---------------------------------------------------------------------------

plugins {
    // 新插件 id。老的 `fabric-loom` 也还在，但 26.2 官方示例用的是这个
    id("net.fabricmc.fabric-loom") version "1.17.20"
    `java`
}

group = "top.kunxun"
version = project.property("mod_version") as String

repositories {
    mavenCentral()
    maven("https://maven.fabricmc.net/") { name = "Fabric" }
}

dependencies {
    minecraft("com.mojang:minecraft:${project.property("minecraft_version")}")

    // 注意这里**没有 mappings(...) 这一行**，而且用的是 implementation 而不是 modImplementation。
    //
    // 原因要从 26.x 说起：Mojang 从 26.2 起不再发布 client_mappings（官方混淆映射表），
    // 因为 26.2 的客户端 jar 本身就是用官方名打包的——net.minecraft.client.Minecraft、
    // net.minecraft.resources.Identifier 这些名字在 jar 里原样存在。
    // 同时 Fabric 的 intermediary 对 26.2 是恒等映射（net.fabricmc:intermediary:0.0.0）。
    //
    // 换句话说：编译期名字 == 运行期名字，**整个 remap 环节消失了**。
    // 所以既不需要 mappings，也不需要 modImplementation（它的唯一作用就是标记「这个依赖要 remap」）。
    // Yarn 在 26.2 上确实不存在，但「没有 Yarn」在这里不是问题，因为没有映射需求。
    implementation("net.fabricmc:fabric-loader:${project.property("fabric_loader_version")}")
    implementation("net.fabricmc.fabric-api:fabric-api:${project.property("fabric_api_version")}")
}

// 三个加载器共用 common 里的协议/密钥/身份三个类。
// 这里是把源码目录「挂」进来而不是建一个独立子模块：独立子模块在 Loom 里
// 需要额外的依赖与 remap 配置，而这三个类根本不碰 Minecraft，挂进来最省事也最不容易出错。
sourceSets {
    main {
        java.srcDirs("../common/src/main/java")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_25
    targetCompatibility = JavaVersion.VERSION_25
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // MC 26.2 跑在 Java 25 上，字节码必须是 25，否则会在类加载阶段抛 UnsupportedClassVersionError
    options.release.set(25)
}

// 交付要求固定产物名：KunxunAuth-Device-1.1.0-fabric.jar
tasks.named<Jar>("jar") {
    archiveFileName.set("KunxunAuth-Device-${project.version}-fabric.jar")
}

// 26.2 没有 remap 环节，理论上不会再生成 remapJar；但如果某个 Loom 版本仍然生成了它，
// 就把名字一起改掉，保证 dist 里只会出现一个符合命名要求的文件。
tasks.matching { it.name == "remapJar" }.configureEach {
    (this as AbstractArchiveTask).archiveFileName.set("KunxunAuth-Device-${project.version}-fabric.jar")
}

tasks.named<ProcessResources>("processResources") {
    // 让 fabric.mod.json 里的 ${version} 能被替换，避免版本号写两处
    inputs.property("version", project.version)
    filesMatching("fabric.mod.json") {
        expand("version" to project.version)
    }
}
