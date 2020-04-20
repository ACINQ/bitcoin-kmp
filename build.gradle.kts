import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeCompilation

buildscript {
    repositories.jcenter()
}

plugins {
    kotlin("multiplatform") version "1.3.72"
    kotlin("plugin.serialization") version "1.3.72"
    `maven-publish`
}

group = "fr.acinq"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    /* Targets configuration omitted. 
    *  To find out how to configure the targets, please follow the link:
    *  https://kotlinlang.org/docs/reference/building-mpp-with-gradle.html#setting-up-targets */
    val cinterop_libsecp256k_location: String by project

    val buildNativeLib = tasks.register<Exec>("build-native-lib") {
        //warning are issued at the end of command by cross-compilation to iOS, but they are only warnings ;-)
        workingDir(project.file(cinterop_libsecp256k_location))
        commandLine("./xbuild-secp256k1.sh")
        outputs.dir("$cinterop_libsecp256k_location/secp256k1/build/ios")
        outputs.dir("$cinterop_libsecp256k_location/secp256k1/build/linux")
    }

    jvm()
    linuxX64("linux")
    targets.configureEach {
        (compilations["main"] as? org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeCompilation)?.apply {
            cinterops {
                val libsecp256k1 by creating {
                    includeDirs.headerFilterOnly(project.file("${cinterop_libsecp256k_location}/secp256k1/include/"))
                    includeDirs(project.file("$cinterop_libsecp256k_location/secp256k1/.libs"), "/usr/local/lib")
                    tasks[interopProcessingTaskName].dependsOn(buildNativeLib)
                }
            }
        }
    }
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(kotlin("stdlib-common"))
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-runtime-common:0.20.0")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(kotlin("stdlib-jdk8"))
                implementation("org.bouncycastle:bcprov-jdk15on:1.64")
                implementation("fr.acinq.bitcoin:secp256k1-jni:1.3")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-runtime:0.20.0")
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.9.8")
                implementation("com.google.guava:guava:28.2-jre")
            }
        }
        val linuxMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-runtime-native:0.20.0")
            }
        }
    }
}