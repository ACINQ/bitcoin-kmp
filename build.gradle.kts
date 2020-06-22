plugins {
    kotlin("multiplatform") version "1.4-M2"
    kotlin("plugin.serialization") version "1.4-M2"
    `maven-publish`
}

group = "fr.acinq"
version = "0.1-1.4-M2"

repositories {
    jcenter()
    maven("https://dl.bintray.com/kotlin/kotlinx")
    maven("https://dl.bintray.com/kotlin/kotlin-eap")
}

kotlin {
    explicitApi()

    /* Targets configuration omitted. 
    *  To find out how to configure the targets, please follow the link:
    *  https://kotlinlang.org/docs/reference/building-mpp-with-gradle.html#setting-up-targets */
    val cinterop_libsecp256k_location: String by extra

    val buildNativeLib = tasks.register<Exec>("build-native-lib") {
        //warning are issued at the end of command by cross-compilation to iOS, but they are only warnings ;-)
        workingDir(project.file(cinterop_libsecp256k_location))
        commandLine("./xbuild-secp256k1.sh")
        outputs.dir("$cinterop_libsecp256k_location/secp256k1/build/ios")
        outputs.dir("$cinterop_libsecp256k_location/secp256k1/build/linux")
    }

    jvm()

    fun org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget.secp256k1CInterop() {
        compilations["main"].cinterops {
            val libsecp256k1 by creating {
                includeDirs.headerFilterOnly(project.file("${cinterop_libsecp256k_location}/secp256k1/include/"))
                includeDirs(project.file("$cinterop_libsecp256k_location/secp256k1/.libs"), "/usr/local/lib")
                tasks[interopProcessingTaskName].dependsOn(buildNativeLib)
            }
        }
    }

    linuxX64("linux") {
        secp256k1CInterop()
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs = listOf("-include-binary", "$rootDir/c/secp256k1/build/linux/libsecp256k1.a")
    }
    ios {
        secp256k1CInterop()
        // https://youtrack.jetbrains.com/issue/KT-39396
        compilations["main"].kotlinOptions.freeCompilerArgs = listOf("-include-binary", "$rootDir/c/secp256k1/build/ios/libsecp256k1.a")
    }

    sourceSets {
        val serialization_version: String by extra

        val commonMain by getting {
            dependencies {
                implementation(kotlin("stdlib-common"))
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-runtime:$serialization_version")
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
            }
        }

        val iosMain by getting {
            dependencies {
            }
        }

        all {
            languageSettings.useExperimentalAnnotation("kotlin.RequiresOptIn")
        }
    }
}

val bintrayUsername: String? = (properties["bintrayUsername"] as String?) ?: System.getenv("BINTRAY_USER")
val bintrayApiKey: String? = (properties["bintrayApiKey"] as String?) ?: System.getenv("BINTRAY_APIKEY")

afterEvaluate {
    tasks["compileIosMainKotlinMetadata"].enabled = false
}

if (bintrayUsername == null || bintrayApiKey == null) logger.warn("Skipping bintray configuration as bintrayUsername or bintrayApiKey is not defined")
else {
    publishing {
        val snapshotName: String? by project
        val snapshotNumber: String? by project

        val snapshot = snapshotName?.let { name -> snapshotNumber?.let { number -> name to number } }

        publications.withType<MavenPublication> {
            if (snapshot != null) version = "${project.version}-${snapshot.first}-${snapshot.second}"
        }

        repositories {
            maven {
                name = "bintray"
                val btRepo = if (snapshotNumber != null) "${rootProject.name}-dev" else rootProject.name
                val btIsSnaphost = if (snapshotNumber != null) 1 else 0
                setUrl("https://api.bintray.com/maven/acinq/$btRepo/${project.name}/;publish=0;override=$btIsSnaphost")
                credentials {
                    username = bintrayUsername
                    password = bintrayApiKey
                }
            }
        }
    }
}

// Disable cross compilation
afterEvaluate {
    val currentOs = org.gradle.internal.os.OperatingSystem.current()
    val targets = when {
        currentOs.isLinux -> listOf()
        currentOs.isMacOsX -> listOf("linux")
        currentOs.isWindows -> listOf("linux")
        else -> listOf("linux")
    }.mapNotNull { kotlin.targets.findByName(it) as? org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget }

    configure(targets) {
        compilations.all {
            cinterops.all { tasks[interopProcessingTaskName].enabled = false }
            compileKotlinTask.enabled = false
            tasks[processResourcesTaskName].enabled = false
        }
        binaries.all { linkTask.enabled = false }

        mavenPublication {
            val publicationToDisable = this
            tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != publicationToDisable } }
            tasks.withType<GenerateModuleMetadata>().all { onlyIf { publication.get() != publicationToDisable } }
        }
    }
}
