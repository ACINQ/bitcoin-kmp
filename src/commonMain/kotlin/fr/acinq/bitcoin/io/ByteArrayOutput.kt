package fr.acinq.bitcoin.io


public class ByteArrayOutput : Output {
    private var array: ByteArray = ByteArray(32)
    private var position: Int = 0

    @OptIn(ExperimentalStdlibApi::class)
    private fun ensureCapacity(elementsToAppend: Int) {
        if (position + elementsToAppend <= array.size) return
        val newArray = ByteArray((position + elementsToAppend).takeHighestOneBit() shl 1)
        array.copyInto(newArray)
        array = newArray
    }

    override fun write(byteValue: Int) {
        ensureCapacity(1)
        array[position++] = byteValue.toByte()
    }

    override fun write(buffer: ByteArray, offset: Int, count: Int) {
        // avoid int overflow
        if (offset < 0 || offset > buffer.size || count < 0 || count > buffer.size - offset) throw IndexOutOfBoundsException()
        if (count == 0) return

        ensureCapacity(count)
        buffer.copyInto(destination = array, destinationOffset = this.position, startIndex = offset, endIndex = offset + count)
        this.position += count
    }

    public fun toByteArray(): ByteArray {
        val newArray = ByteArray(position)
        array.copyInto(newArray, startIndex = 0, endIndex = this.position)
        return newArray
    }
}
