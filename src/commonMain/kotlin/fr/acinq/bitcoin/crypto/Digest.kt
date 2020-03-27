package fr.acinq.bitcoin.crypto

interface Digest {
    /**
     * return the algorithm name
     *
     * @return the algorithm name
     */
    fun getAlgorithmName(): String

    /**
     * return the size, in bytes, of the digest produced by this message digest.
     *
     * @return the size, in bytes, of the digest produced by this message digest.
     */
    fun getDigestSize(): Int

    /**
     * update the message digest with a single byte.
     *
     * @param `in` the input byte to be entered.
     */
    fun update(input: Byte)

    /**
     * update the message digest with a block of bytes.
     *
     * @param `in` the byte array containing the data.
     * @param inputOffset the offset into the byte array where the data starts.
     * @param len the length of the data.
     */
    fun update(input: ByteArray, inputOffset: Int, len: Int)

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     *
     * @param out the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     */
    fun doFinal(out: ByteArray, outOffset: Int): Int

    /**
     * reset the digest back to it's initial state.
     */
    fun reset()

    fun hash(input: ByteArray, inputOffset: Int, len: Int): ByteArray {
        reset()
        update(input, inputOffset, len)
        val output = ByteArray(getDigestSize())
        doFinal(output, 0)
        return output
    }

    fun hash(input: ByteArray) = hash(input, 0, input.size)
}