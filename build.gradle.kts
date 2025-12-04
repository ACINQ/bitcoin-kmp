import org.jetbrains.dokka.Platform
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.KotlinJvmTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeHostTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest

plugins {
    kotlin("multiplatform") version "2.2.0"
    id("org.jetbrains.dokka") version "1.9.20"
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

group = "fr.acinq.bitcoin"
version = "0.29.0-SNAPSHOT"

repositories {
    google()
    mavenCentral()
}

kotlin {
    explicitApi()

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
            // See https://jakewharton.com/kotlins-jdk-release-compatibility-flag/ and https://youtrack.jetbrains.com/issue/KT-49746/
            freeCompilerArgs.add("-Xjdk-release=1.8")
        }
    }

    java {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    linuxX64()

    linuxArm64()

    macosX64()
    
    macosArm64()

    iosX64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }

    iosArm64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }

    iosSimulatorArm64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }

    sourceSets {
        val secp256k1KmpVersion = "0.21.0"

        val commonMain by getting {
            dependencies {
                api("fr.acinq.secp256k1:secp256k1-kmp:$secp256k1KmpVersion")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
                implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.8.0")
                api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                val target = when {
                    currentOs.isLinux -> "linux"
                    currentOs.isMacOsX -> "darwin"
                    currentOs.isWindows -> "mingw"
                    else -> error("Unsupported OS $currentOs")
                }
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-$target:$secp256k1KmpVersion")
            }
        }

        all {
            languageSettings.optIn("kotlin.RequiresOptIn")
        }
    }

    // Configure all compilations of all targets:
    targets.all {
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions {
                    allWarningsAsErrors = true
                    // See https://youtrack.jetbrains.com/issue/KT-61573
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                }
            }
        }
    }
}

configurations.forEach {
    // do not cache changing (i.e. SNAPSHOT) dependencies
    it.resolutionStrategy.cacheChangingModulesFor(0, TimeUnit.SECONDS)

    if (it.name.contains("testCompileClasspath")) {
        it.attributes.attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage::class.java, "java-runtime"))
    }
}


// Disable cross compilation
plugins.withId("org.jetbrains.kotlin.multiplatform") {
    afterEvaluate {
        val currentOs = org.gradle.internal.os.OperatingSystem.current()
        val targets = when {
            currentOs.isLinux -> listOf()
            else -> listOf("linuxX64")
        }.mapNotNull { kotlin.targets.findByName(it) as? org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget }

        configure(targets) {
            compilations.all {
                cinterops.all { tasks[interopProcessingTaskName].enabled = false }
                compileTaskProvider.configure {
                    enabled = false
                }
                tasks[processResourcesTaskName].enabled = false
            }
            binaries.all {
                linkTaskProvider.configure {
                    enabled = false
                }
            }

            mavenPublication {
                val publicationToDisable = this
                tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != publicationToDisable } }
                tasks.withType<GenerateModuleMetadata>().all { onlyIf { publication.get() != publicationToDisable } }
            }
        }
    }
}

val dokkaOutputDir = layout.buildDirectory.dir("dokka")

tasks.dokkaHtml {
    outputDirectory.set(file(dokkaOutputDir))
    dokkaSourceSets {
        configureEach {
            val platformName = when (platform.get()) {
                Platform.jvm -> "jvm"
                Platform.js -> "js"
                Platform.native -> "native"
                Platform.common -> "common"
                Platform.wasm -> "wasm"
                else -> error("unexpected platform ${platform.get()}")
            }
            displayName.set(platformName)

            perPackageOption {
                matchingRegex.set(".*\\.internal.*") // will match all .internal packages and sub-packages
                suppress.set(true)
            }
        }
    }
}

val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
    delete(dokkaOutputDir)
}


val javadocJar = tasks.create<Jar>("javadocJar") {
    archiveClassifier.set("javadoc")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    dependsOn(deleteDokkaOutputDir, tasks.dokkaHtml)
    from(dokkaOutputDir)
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        version = project.version.toString()
        artifact(javadocJar)
        pom {
            name.set("Kotlin Multiplatform Bitcoin Library")
            description.set("A simple Kotlin Multiplatform library which implements most of the bitcoin protocol")
            url.set("https://github.com/ACINQ/bitcoin-kmp")
            licenses {
                license {
                    name.set("Apache License v2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0")
                }
            }
            issueManagement {
                system.set("Github")
                url.set("https://github.com/ACINQ/bitcoin-kmp/issues")
            }
            scm {
                connection.set("https://github.com/ACINQ/bitcoin-kmp.git")
                url.set("https://github.com/ACINQ/bitcoin-kmp")
            }
            developers {
                developer {
                    name.set("ACINQ")
                    email.set("hello@acinq.co")
                }
            }
        }
    }
}

afterEvaluate {
    tasks.withType<AbstractTestTask> {
        testLogging {
            events("passed", "skipped", "failed", "standard_out", "standard_error")
            showExceptions = true
            showStackTraces = true
        }
    }

    tasks.withType<KotlinJvmTest> {
        environment("TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }

    tasks.withType<KotlinNativeHostTest> {
        environment("TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }

    tasks.withType<KotlinNativeSimulatorTest> {
        environment("SIMCTL_CHILD_TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }
}
