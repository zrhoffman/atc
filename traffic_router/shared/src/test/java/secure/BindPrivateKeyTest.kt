/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package secure

import com.comcast.cdn.traffic_control.traffic_router.secure.BindPrivateKey
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import sun.security.rsa.RSAPrivateCrtKeyImpl
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.RSAPrivateCrtKeySpec
import java.util.Base64

@RunWith(PowerMockRunner::class)
@PrepareForTest(BindPrivateKey::class)
class BindPrivateKeyTest {
    private var privateKeyString: String? = null
    private var privateKey: PrivateKey? = null
    fun encode(bigInteger: BigInteger?): String? {
        return String(Base64.getEncoder().encode(bigInteger.toByteArray()))
    }

    @Before
    @Throws(Exception::class)
    fun before() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048, SecureRandom.getInstance("SHA1PRNG", "SUN"))
        val keyPair = keyPairGenerator.generateKeyPair()
        val privateCrtKey = keyPair.private as RSAPrivateCrtKeyImpl
        privateKeyString = """
            Private-key-format: v1.2
            Algorithm: 5 (RSASHA1)
            Modulus: ${encode(privateCrtKey.modulus)}
            PublicExponent: ${encode(privateCrtKey.publicExponent)}
            PrivateExponent: ${encode(privateCrtKey.privateExponent)}
            Prime1: ${encode(privateCrtKey.primeP)}
            Prime2: ${encode(privateCrtKey.primeQ)}
            Exponent1: ${encode(privateCrtKey.primeExponentP)}
            Exponent2: ${encode(privateCrtKey.primeExponentQ)}
            Coefficient: ${encode(privateCrtKey.crtCoefficient)}
            
            """.trimIndent()
        privateKey = Mockito.mock(PrivateKey::class.java)
        val keyFactory = PowerMockito.mock(KeyFactory::class.java)
        PowerMockito.mockStatic(KeyFactory::class.java)
        PowerMockito.`when`(KeyFactory.getInstance("RSA")).thenReturn(keyFactory)
        val spec = Mockito.mock(RSAPrivateCrtKeySpec::class.java)
        PowerMockito.whenNew(RSAPrivateCrtKeySpec::class.java)
            .withArguments(
                privateCrtKey.modulus,
                privateCrtKey.publicExponent,
                privateCrtKey.privateExponent,
                privateCrtKey.primeP,
                privateCrtKey.primeQ,
                privateCrtKey.primeExponentP,
                privateCrtKey.primeExponentQ,
                privateCrtKey.crtCoefficient
            )
            .thenReturn(spec)
        PowerMockito.doReturn(privateKey).`when`(keyFactory).generatePrivate(spec)
    }

    @Test
    fun itDecodesPrivateKeyString() {
        val key = BindPrivateKey().decode(privateKeyString)
        MatcherAssert.assertThat(key, Matchers.equalTo(privateKey))
    }
}