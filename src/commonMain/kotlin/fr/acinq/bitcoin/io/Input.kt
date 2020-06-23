package fr.acinq.bitcoin.io

public interface Input {
    public val availableBytes: Int
    public fun read(): Int
    public fun read(b: ByteArray, offset: Int = 0, length: Int = b.size - offset): Int
}

public fun Input.readNBytes(n: Int): ByteArray = ByteArray(n).also { read(it, 0, n) }
