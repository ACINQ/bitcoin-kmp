package fr.acinq.bitcoin.crypto

import kotlin.experimental.xor

object Pbkdf2 {
   fun generate(p: ByteArray, s: ByteArray, c: Int, dkLen: Int, digest: Digest) : ByteArray {
       val hLen = digest.getDigestSize()
       val l = kotlin.math.ceil(dkLen.toFloat() / hLen).toInt()
       val r = dkLen - (l - 1)*hLen

       fun prf(input: ByteArray) = HMac.hmac(p, input, digest, 128)

       fun xor(a: ByteArray, b:ByteArray){
           require(a.size == b.size)
           for(i in a.indices) {
               a[i] = a[i] xor b[i]
           }
       }

       fun f(i: Int) : ByteArray {
           var u = prf(s + Pack.writeUint32BE(i))
           var output = u.copyOf()
           for(i in 1 until c) {
               u = prf(u)
               xor(output, u)
           }
           return output
       }

       var t = f(1)
       for(i in 2 until l) {
           t += f(i)
       }
       return t
   }
}