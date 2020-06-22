package fr.acinq.bitcoin.io


public class ByteArrayInput(private val array: ByteArray) : Input {

    private var position: Int = 0
    override val availableBytes: Int get() = array.size - position

    override fun read(): Int {
        return if (position < array.size) array[position++].toInt() and 0xFF else -1
    }

    override fun read(b: ByteArray, offset: Int, length: Int): Int {
        if (offset < 0 || offset > b.size || length < 0 || length > b.size - offset) throw IndexOutOfBoundsException()
        if (this.position >= array.size) return -1
        if (length == 0) return 0

        val copied = if (array.size - position < length) array.size - position else length
        array.copyInto(destination = b, destinationOffset = offset, startIndex = position, endIndex = position + copied)
        position += copied

        return copied
    }
}
