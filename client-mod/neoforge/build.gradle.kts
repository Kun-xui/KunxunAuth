// ---------------------------------------------------------------------------
// KunxunAuth Device —— NeoForge 26.2 客户端模组
// ---------------------------------------------------------------------------

plugins {
    id("net.neoforged.moddev") version "2.0.147"
    `java`
}

group = "top.kunxun"
version = project.property("mod_version") as String

repositories {
    mavenCentral()
    maven("https://maven.neoforged.net/releases") { name = "NeoForged" }
}

neoForge {
    version = project.property("neoforge_version") as String

    // 声明本模组包含哪些源码集，ModDevGradle 靠这个生成运行配置和 mods.toml 的校验
    mods {
        register("kunxunauth_device") {
            sourceSet(sourceSets.main.get())
        }
    }

    // 只声明客户端运行配置：这是个纯客户端模组，起服务端没有意义，也省一次启动时间
    runs {
        register("client") {
            client()
        }
    }
}

// 与 Fabric 侧完全相同的做法：把 common 的源码目录挂进来。
// 这三个类不引用任何 Minecraft 类，因此不需要（也不应该）参与 NeoForge 的映射处理。
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
    // MC 26.2 跑在 Java 25 上，字节码必须是 25
    options.release.set(25)
}

// 交付要求固定产物名：KunxunAuth-Device-1.0.0-neoforge.jar
tasks.named<Jar>("jar") {
    archiveFileName.set("KunxunAuth-Device-${project.version}-neoforge.jar")
}

tasks.named<ProcessResources>("processResources") {
    inputs.property("version", project.version)
    filesMatching("META-INF/neoforge.mods.toml") {
        expand("version" to project.version)
    }
}
