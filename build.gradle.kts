plugins {
    kotlin("multiplatform") version "1.4-M2-mt"
    `maven-publish`
}

group = "fr.acinq"
version = "0.1.0-1.4-M2"

repositories {
    mavenLocal()
    google()
    maven("https://dl.bintray.com/kotlin/kotlinx")
    maven("https://dl.bintray.com/kotlin/kotlin-eap")
    maven("https://dl.bintray.com/acinq/libs")
    jcenter()
}

kotlin {
    explicitApi()

    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
    }

    linuxX64("linux")

    ios()

    sourceSets {
        val secp256k1KmpVersion = "0.1.0-1.4-M2"

        val commonMain by getting {
            dependencies {
                implementation(kotlin("stdlib-common"))
                api("fr.acinq.secp256k1:secp256k1-kmp:$secp256k1KmpVersion")
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
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.11.0")
                implementation("fr.acinq.secp256k1:secp256k1-jni-jvm:$secp256k1KmpVersion")
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

// Disable cross compilation
allprojects {
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        afterEvaluate {
            val currentOs = org.gradle.internal.os.OperatingSystem.current()
            val targets = when {
                currentOs.isLinux -> listOf()
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
    }
}

publishing {
    val snapshotNumber: String? by project

    val bintrayUsername: String? = (properties["bintrayUsername"] as String?) ?: System.getenv("BINTRAY_USER")
    val bintrayApiKey: String? = (properties["bintrayApiKey"] as String?) ?: System.getenv("BINTRAY_APIKEY")
    if (bintrayUsername == null || bintrayApiKey == null) logger.warn("Skipping bintray configuration as bintrayUsername or bintrayApiKey is not defined")
    else {
        val btRepo = if (snapshotNumber != null) "snapshots" else "libs"
        val btPublish = if (snapshotNumber != null) "1" else "0"
        repositories {
            maven {
                name = "bintray"
                setUrl("https://api.bintray.com/maven/acinq/$btRepo/${rootProject.name}/;publish=$btPublish")
                credentials {
                    username = bintrayUsername
                    password = bintrayApiKey
                }
            }
        }
    }

    val gitRef: String? by project
    val gitSha: String? by project
    val eapBranch = gitRef?.split("/")?.last() ?: "dev"
    val eapSuffix = gitSha?.let { "-${it.substring(0, 7)}" } ?: ""
    publications.withType<MavenPublication>().configureEach {
        if (snapshotNumber != null) version = "${project.version}-$eapBranch-$snapshotNumber$eapSuffix"
        pom {
            description.set("A simple Kotlin Multiplatform library which implements most of the bitcoin protocol")
            url.set("https://github.com/ACINQ/bitcoink")
            licenses {
                name.set("Apache License v2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0")
            }
            issueManagement {
                system.set("Github")
                url.set("https://github.com/ACINQ/bitcoink/issues")
            }
            scm {
                connection.set("https://github.com/ACINQ/bitcoink.git")
            }
        }
    }
}
