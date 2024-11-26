package fr.acinq.bitcoin

import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readByteArray
import kotlinx.io.readString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

object TestHelpers {
    val resourcesPath = Path(readEnvironmentVariable("TEST_RESOURCES_PATH")?: "src/commonTest/resources")

    fun readResourceAsJson(filename: String): JsonElement {
        val raw = SystemFileSystem.source(Path(resourcesPath, filename)).buffered().readString()
        val format = Json { ignoreUnknownKeys = true }
        return format.parseToJsonElement(raw)
    }


    fun readResourceAsByteArray(filename: String): ByteArray {
        return SystemFileSystem.source(Path(resourcesPath, filename)).buffered().readByteArray()
    }
}

expect fun readEnvironmentVariable(name: String): String?
