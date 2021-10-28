package fr.acinq.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class BtcAmountTestsCommon {

    @Test
    fun `enforce finite bitcoin supply`() {
        assertEquals(21e6.btc().toMilliBtc(), 21e9.mbtc())
        assertFails { (21e6 + 1).btc() }
        assertFails { (21e9 + 1).mbtc() }
    }

    @Test
    fun `conversions between bitcoin units`() {
        val x = 12.34567.btc()
        val y = x.toMilliBtc()
        val z = x.toSatoshi()
        val z1 = y.toSatoshi()
        assertEquals(12.34567, x.toDouble())
        assertEquals(12, x.toLong())
        assertEquals(12345.67, y.toDouble())
        assertEquals(12345, y.toLong())
        assertEquals(z, z1)
        assertEquals(1234567000, z.toLong())
        assertEquals(0.00000001.btc(), 1.sat().toBtc())
        assertEquals(0.00001.mbtc(), 1.sat().toMilliBtc())
        assertEquals(x.toMilliBtc().toBtc(), x)
        assertEquals(y.toBtc().toMilliBtc(), y)
        assertEquals(z.toBtc().toSatoshi(), z)
        assertEquals(z.toMilliBtc().toSatoshi(), z)
    }

    @Test
    fun `negate amount`() {
        assertEquals(Satoshi(-20), -Satoshi(20))
        assertEquals(MilliBtc(-1.5), -MilliBtc(1.5))
        assertEquals(Btc(-2.5), -Btc(2.5))
    }

    @Test
    fun `max and min`() {
        assertEquals(100.sat().max(101.sat()), 101.sat())
        assertEquals(100.sat().min(101.sat()), 100.sat())
        assertEquals(100000.sat().max(0.999.mbtc().toSatoshi()), 100000.sat())
        assertEquals(100000.sat().min(0.999.mbtc().toSatoshi()), 99900.sat())
        assertEquals(100000000.sat().max(0.999.btc().toSatoshi()), 100000000.sat())
        assertEquals(100000000.sat().min(0.999.btc().toSatoshi()), 99900000.sat())
        assertEquals(100.mbtc().max(101.mbtc()), 101.mbtc())
        assertEquals(100.mbtc().min(101.mbtc()), 100.mbtc())
        assertEquals(1.mbtc().max(0.9.mbtc()), 1.mbtc())
        assertEquals(1.mbtc().min(0.9.mbtc()), 0.9.mbtc())
        assertEquals(100.mbtc().max(0.2.btc().toMilliBtc()), 200.mbtc())
        assertEquals(100.mbtc().min(0.2.btc().toMilliBtc()), 100.mbtc())
        assertEquals(1.1.btc().max(0.9.btc()), 1.1.btc())
        assertEquals(1.1.btc().min(0.9.btc()), 0.9.btc())
    }

}