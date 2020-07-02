rootProject.name = "bitcoink"

pluginManagement {
    repositories {
        google()
        maven("https://dl.bintray.com/kotlin/kotlin-eap")
        gradlePluginPortal()
        jcenter()
    }

    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "com.android.library") useModule("com.android.tools.build:gradle:${requested.version}")
        }
    }
}
