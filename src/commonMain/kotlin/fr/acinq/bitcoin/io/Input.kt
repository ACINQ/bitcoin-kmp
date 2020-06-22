package fr.acinq.bitcoin.io

public interface Input {
    public val availableBytes: Int
    public fun read(): Int
    public fun read(b: ByteArray, offset: Int, length: Int): Int
}
