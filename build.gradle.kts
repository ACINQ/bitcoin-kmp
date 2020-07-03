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

val bintrayUsername: String? = (properties["bintrayUsername"] as String?) ?: System.getenv("BINTRAY_USER")
val bintrayApiKey: String? = (properties["bintrayApiKey"] as String?) ?: System.getenv("BINTRAY_APIKEY")

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
