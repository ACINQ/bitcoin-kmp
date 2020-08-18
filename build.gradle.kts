import org.gradle.internal.impldep.org.apache.http.auth.UsernamePasswordCredentials
import org.gradle.internal.impldep.org.apache.http.client.methods.HttpPost
import org.gradle.internal.impldep.org.apache.http.entity.ContentType
import org.gradle.internal.impldep.org.apache.http.impl.client.HttpClients
import org.gradle.internal.impldep.org.apache.http.entity.StringEntity
import org.gradle.internal.impldep.org.apache.http.impl.auth.BasicScheme

plugins {
    kotlin("multiplatform") version "1.4.0"
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

group = "fr.acinq.bitcoink"
version = "0.5.0"

repositories {
    mavenLocal()
    google()
    maven("https://dl.bintray.com/kotlin/kotlinx")
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
        val secp256k1KmpVersion = "0.3.0"

        val commonMain by getting {
            dependencies {
                api("fr.acinq.secp256k1:secp256k1:$secp256k1KmpVersion")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.11.0")
                val target = when {
                    currentOs.isLinux -> "linux"
                    currentOs.isMacOsX -> "darwin"
                    currentOs.isWindows -> "mingw"
                    else -> error("UnsupportedmOS $currentOs")
                }
                implementation("fr.acinq.secp256k1:secp256k1-jni-jvm-$target:$secp256k1KmpVersion")
            }
        }

        all {
            languageSettings.useExperimentalAnnotation("kotlin.RequiresOptIn")
        }
    }
}

// Disable cross compilation
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

val snapshotNumber: String? by project
val gitRef: String? by project
val eapBranch = gitRef?.split("/")?.last() ?: "dev"
val bintrayVersion = if (snapshotNumber != null) "${project.version}-$eapBranch-$snapshotNumber" else project.version.toString()
val bintrayRepo = if (snapshotNumber != null) "snapshots" else "libs"

val bintrayUsername: String? = (properties["bintrayUsername"] as String?) ?: System.getenv("BINTRAY_USER")
val bintrayApiKey: String? = (properties["bintrayApiKey"] as String?) ?: System.getenv("BINTRAY_APIKEY")
val hasBintray = bintrayUsername != null && bintrayApiKey != null
if (!hasBintray) logger.warn("Skipping bintray configuration as bintrayUsername or bintrayApiKey is not defined")

publishing {
    if (hasBintray) {
        repositories {
            maven {
                name = "bintray"
                setUrl("https://api.bintray.com/maven/acinq/$bintrayRepo/${rootProject.name}/;publish=0")
                credentials {
                    username = bintrayUsername
                    password = bintrayApiKey
                }
            }
        }
    }

    publications.withType<MavenPublication>().configureEach {
        version = bintrayVersion
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

if (hasBintray) {
    val postBintrayPublish by tasks.creating {
        doLast {
            HttpClients.createDefault().use { client ->
                val post = HttpPost("https://api.bintray.com/content/acinq/$bintrayRepo/${rootProject.name}/$bintrayVersion/publish").apply {
                    entity = StringEntity("{}", ContentType.APPLICATION_JSON)
                    addHeader(BasicScheme().authenticate(UsernamePasswordCredentials(bintrayUsername, bintrayApiKey), this, null))
                }
                client.execute(post)
            }
        }
    }

    val postBintrayDiscard by tasks.creating {
        doLast {
            HttpClients.createDefault().use { client ->
                val post = HttpPost("https://api.bintray.com/content/acinq/$bintrayRepo/${rootProject.name}/$bintrayVersion/publish").apply {
                    entity = StringEntity("{ \"discard\": true }", ContentType.APPLICATION_JSON)
                    addHeader(BasicScheme().authenticate(UsernamePasswordCredentials(bintrayUsername, bintrayApiKey), this, null))
                }
                client.execute(post)
            }
        }
    }
}

afterEvaluate {
    tasks.withType<AbstractTestTask>() {
        testLogging {
            events("passed", "skipped", "failed", "standard_out", "standard_error")
            showExceptions = true
            showStackTraces = true
        }
    }
}
