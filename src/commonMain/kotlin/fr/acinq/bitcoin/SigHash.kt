package fr.acinq.bitcoin

object SigHash {
    const val SIGHASH_ALL = 1
    const val SIGHASH_NONE = 2
    const val SIGHASH_SINGLE = 3
    const val SIGHASH_ANYONECANPAY = 0x80

    fun isAnyoneCanPay(sighashType: Int): Boolean = (sighashType and SIGHASH_ANYONECANPAY) != 0

    fun isHashSingle(sighashType: Int): Boolean = (sighashType and 0x1f) == SIGHASH_SINGLE

    fun isHashNone(sighashType: Int): Boolean = (sighashType and 0x1f) == SIGHASH_NONE
}

object SigVersion {
    const val SIGVERSION_BASE = 0
    const val SIGVERSION_WITNESS_V0 = 1
}
