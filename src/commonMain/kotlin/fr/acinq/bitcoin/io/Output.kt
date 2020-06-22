package fr.acinq.bitcoin.io

public interface Output {
    public fun write(buffer: ByteArray, offset: Int = 0, count: Int = buffer.size)
    public fun write(byteValue: Int)
}
