package fr.acinq.bitcoin.io

import java.io.OutputStream

public class OutputStreamOutput(private val stream: OutputStream) : Output {

    override fun write(buffer: ByteArray, offset: Int, count: Int) {
        stream.write(buffer, offset, count)
    }

    override fun write(byteValue: Int) {
        stream.write(byteValue)
    }
}
