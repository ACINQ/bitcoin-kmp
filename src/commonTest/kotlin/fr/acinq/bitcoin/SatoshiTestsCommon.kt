package fr.acinq.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals

class SatoshiTestsCommon {

    @Test
    fun `numeric operations`() {
        assertEquals(Satoshi(-20), -Satoshi(20))
        assertEquals(Satoshi(30) + Satoshi(20) * 2 + Satoshi(50) / 2 - Satoshi(5), 90.sat())
        assertEquals(100.sat().max(101.sat()), 101.sat())
        assertEquals(100.sat().min(101.sat()), 100.sat())
    }

}