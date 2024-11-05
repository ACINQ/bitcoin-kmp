package fr.acinq.bitcoin

actual fun readEnvironmentVariable(name: String): String? {
    return System.getenv(name)
}