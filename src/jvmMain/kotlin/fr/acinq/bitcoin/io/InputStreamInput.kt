package fr.acinq.bitcoin.io

import java.io.InputStream


public class InputStreamInput(private val stream: InputStream) : Input {

    override val availableBytes: Int get() = stream.available()

    override fun read(): Int = stream.read()

    override fun read(b: ByteArray, offset: Int, length: Int): Int = stream.read(b, offset, length)
}
