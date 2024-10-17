package sh.autograph

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KeyPairTest {
    @Before
    fun init() {
        ready()
    }

    @Test
    fun testGenerateIdentityKeyPair() {
        val keyPair = generateIdentityKeyPair()
        assertEquals(keyPair.size, 64)
        assertFalse(keyPair.all { it == 0.toByte() })
    }

    @Test
    fun testGenerateSessionKeyPair() {
        val keyPair = generateSessionKeyPair()
        assertEquals(keyPair.size, 64)
        assertFalse(keyPair.all { it == 0.toByte() })
    }
}
