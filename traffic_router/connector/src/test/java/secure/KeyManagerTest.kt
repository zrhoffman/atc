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

import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry
import com.comcast.cdn.traffic_control.traffic_router.secure.HandshakeData
import com.comcast.cdn.traffic_control.traffic_router.secure.KeyManager
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Arrays
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLSocket

@RunWith(PowerMockRunner::class)
@PrepareForTest(CertificateRegistry::class)
class KeyManagerTest {
    private var keyManager: KeyManager? = null
    private var x509Certificate: X509Certificate? = null
    private var privateKey: PrivateKey? = null

    @Before
    @Throws(Exception::class)
    fun before() {
        privateKey = Mockito.mock(PrivateKey::class.java)
        x509Certificate = Mockito.mock(X509Certificate::class.java)
        val x509Certificates = arrayOf(
            x509Certificate
        )
        val handshakeData = Mockito.mock(HandshakeData::class.java)
        Mockito.`when`(handshakeData.certificateChain).thenReturn(x509Certificates)
        Mockito.`when`(handshakeData.privateKey).thenReturn(privateKey)
        val certificateRegistry = Mockito.mock(
            CertificateRegistry::class.java
        )
        Mockito.`when`(certificateRegistry.aliases).thenReturn(
            Arrays.asList(
                "deliveryservice3.cdn2.example.com",
                "deliveryservice2.cdn2.example.com"
            )
        )
        PowerMockito.mockStatic(CertificateRegistry::class.java)
        Mockito.`when`<CertificateRegistry?>(CertificateRegistry.Companion.getInstance())
            .thenReturn(certificateRegistry)
        Mockito.`when`(certificateRegistry.getHandshakeData("deliveryservice2.cdn2.example.com"))
            .thenReturn(handshakeData)
        keyManager = KeyManager()
    }

    @Test
    fun itSelectsServerAlias() {
        val sniServerNames: MutableList<SNIServerName?> = ArrayList()
        sniServerNames.add(TestSNIServerName(1, "tr.deliveryservice1.cdn1.example.com"))
        sniServerNames.add(TestSNIServerName(1, "tr.deliveryservice2.cdn2.example.com"))
        val sslExtendedSession = Mockito.mock(
            ExtendedSSLSession::class.java
        )
        Mockito.`when`(sslExtendedSession.requestedServerNames).thenReturn(sniServerNames)
        val sslSocket = Mockito.mock(SSLSocket::class.java)
        Mockito.`when`(sslSocket.handshakeSession).thenReturn(sslExtendedSession)
        val serverAlias = keyManager.chooseServerAlias("RSA", null, sslSocket)
        MatcherAssert.assertThat(serverAlias, Matchers.equalTo("deliveryservice2.cdn2.example.com"))
    }

    @Test
    fun itGetsCertFromRegistry() {
        MatcherAssert.assertThat(
            keyManager.getCertificateChain("deliveryservice2.cdn2.example.com")[0],
            Matchers.equalTo(x509Certificate)
        )
    }

    @Test
    fun itGetsKeyFromRegistry() {
        MatcherAssert.assertThat(
            keyManager.getPrivateKey("deliveryservice2.cdn2.example.com"),
            Matchers.equalTo(privateKey)
        )
    }

    internal inner class TestSNIServerName(type: Int, name: String?) : SNIServerName(type, name.toByteArray())
}