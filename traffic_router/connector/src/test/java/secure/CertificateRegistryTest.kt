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

import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterNioEndpoint
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataConverter
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry
import com.comcast.cdn.traffic_control.traffic_router.secure.HandshakeData
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.util.Arrays

class CertificateRegistryTest {
    private val certificateRegistry: CertificateRegistry? = CertificateRegistry.Companion.getInstance()
    private var certificateDataList: MutableList<*>? = null
    private var certificateDataConverter: CertificateDataConverter? = null
    private var certificateData1: CertificateData? = null
    private var certificateData2: CertificateData? = null
    private var certificateData3: CertificateData? = null
    private var handshakeData1: HandshakeData? = null
    private var handshakeData2: HandshakeData? = null
    private var handshakeData3: HandshakeData? = null

    @Before
    @Throws(Exception::class)
    fun before() {
        certificateData1 = Mockito.mock(CertificateData::class.java)
        certificateData2 = Mockito.mock(CertificateData::class.java)
        certificateData3 = Mockito.mock(CertificateData::class.java)
        Mockito.`when`(certificateData1.alias()).thenReturn("ds-1.some-cdn.example.com")
        Mockito.`when`(certificateData2.alias()).thenReturn("ds-2.some-cdn.example.com")
        Mockito.`when`(certificateData3.alias()).thenReturn("ds-3.some-cdn.example.com")
        certificateDataList = ArrayList<Any?>(Arrays.asList(certificateData1, certificateData2, certificateData3))
        handshakeData1 = Mockito.mock(HandshakeData::class.java)
        Mockito.`when`(handshakeData1.getHostname()).thenReturn("*.ds-1.some-cdn.example.com")
        handshakeData2 = Mockito.mock(HandshakeData::class.java)
        Mockito.`when`(handshakeData2.getHostname()).thenReturn("*.ds-2.some-cdn.example.com")
        handshakeData3 = Mockito.mock(HandshakeData::class.java)
        Mockito.`when`(handshakeData3.getHostname()).thenReturn("*.ds-3.some-cdn.example.com")
        certificateDataConverter = Mockito.mock(CertificateDataConverter::class.java)
        Mockito.`when`(certificateDataConverter.toHandshakeData(certificateData1)).thenReturn(handshakeData1)
        Mockito.`when`(certificateDataConverter.toHandshakeData(certificateData2)).thenReturn(handshakeData2)
        Mockito.`when`(certificateDataConverter.toHandshakeData(certificateData3)).thenReturn(handshakeData3)
        certificateRegistry.setCertificateDataConverter(certificateDataConverter)
    }

    @Test
    @Throws(Exception::class)
    fun itImportsCertificateData() {
        certificateRegistry.importCertificateDataList(certificateDataList)
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-1.some-cdn.example.com"),
            Matchers.equalTo(handshakeData1)
        )
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-2.some-cdn.example.com"),
            Matchers.equalTo(handshakeData2)
        )
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-3.some-cdn.example.com"),
            Matchers.equalTo(handshakeData3)
        )
        Mockito.verify(certificateDataConverter).toHandshakeData(certificateData1)
        Mockito.verify(certificateDataConverter).toHandshakeData(certificateData2)
        Mockito.verify(certificateDataConverter).toHandshakeData(certificateData3)
        MatcherAssert.assertThat(
            certificateRegistry.getAliases(),
            Matchers.containsInAnyOrder<String?>(
                CertificateRegistry.Companion.DEFAULT_SSL_KEY, "ds-1.some-cdn.example.com",
                "ds-2.some-cdn.example.com", "ds-3.some-cdn.example.com"
            )
        )
    }

    @Test
    @Throws(Exception::class)
    fun itRetrysCertificateDataOnEndpointFail() {
        val handshakeData3mod = Mockito.mock(HandshakeData::class.java)
        Mockito.`when`(handshakeData3mod.hostname).thenReturn("*.ds-3.some-cdn.example.com")
        val certificateData3mod = Mockito.mock(CertificateData::class.java)
        Mockito.`when`(certificateData3mod.alias()).thenReturn("ds-3.some-cdn.example.com")
        Mockito.`when`(certificateDataConverter.toHandshakeData(certificateData3mod)).thenReturn(handshakeData3mod)
        certificateDataList.remove(certificateData3)
        certificateDataList.add(certificateData3mod)
        val endpoint = Mockito.mock(RouterNioEndpoint::class.java)
        val failist: MutableList<String?> = ArrayList()
        failist.add("ds-3.some-cdn.example.com")
        Mockito.`when`<MutableList<*>?>(endpoint.reloadSSLHosts(org.mockito.Matchers.anyMap())).thenReturn(failist)
        certificateRegistry.setEndPoint(endpoint)
        certificateRegistry.importCertificateDataList(certificateDataList)
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-1.some-cdn.example.com"),
            Matchers.equalTo(handshakeData1)
        )
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-2.some-cdn.example.com"),
            Matchers.equalTo(handshakeData2)
        )
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-3.some-cdn.example.com"),
            Matchers.equalTo(handshakeData3mod)
        )
        Mockito.verify(certificateDataConverter).toHandshakeData(certificateData1)
        Mockito.verify(certificateDataConverter).toHandshakeData(certificateData2)
        Mockito.verify(certificateDataConverter).toHandshakeData(certificateData3mod)
        Mockito.verify(endpoint).reloadSSLHosts(org.mockito.Matchers.anyMap())
        MatcherAssert.assertThat(
            certificateRegistry.getAliases(),
            Matchers.containsInAnyOrder<String?>(
                CertificateRegistry.Companion.DEFAULT_SSL_KEY,
                "ds-1.some-cdn.example.com",
                "ds-2.some-cdn.example.com",
                "ds-3.some-cdn.example.com"
            )
        )

        // try again
        // we should see that reloadSSLHosts gets called again even though none of the inputs have changed
        Mockito.`when`<MutableList<*>?>(endpoint.reloadSSLHosts(org.mockito.Matchers.anyMap()))
            .thenReturn(ArrayList<Any?>())
        certificateRegistry.importCertificateDataList(certificateDataList)
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-1.some-cdn.example.com"),
            Matchers.equalTo(handshakeData1)
        )
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-2.some-cdn.example.com"),
            Matchers.equalTo(handshakeData2)
        )
        MatcherAssert.assertThat(
            certificateRegistry.getHandshakeData("ds-3.some-cdn.example.com"),
            Matchers.equalTo(handshakeData3mod)
        )
        Mockito.verify(certificateDataConverter, Mockito.times(2)).toHandshakeData(certificateData1)
        Mockito.verify(certificateDataConverter, Mockito.times(2)).toHandshakeData(certificateData2)
        Mockito.verify(certificateDataConverter, Mockito.times(2)).toHandshakeData(certificateData3mod)
        Mockito.verify(endpoint, Mockito.times(2)).reloadSSLHosts(org.mockito.Matchers.anyMap())
        MatcherAssert.assertThat(
            certificateRegistry.getAliases(),
            Matchers.containsInAnyOrder<String?>(
                CertificateRegistry.Companion.DEFAULT_SSL_KEY,
                "ds-1.some-cdn.example.com",
                "ds-2.some-cdn.example.com",
                "ds-3.some-cdn.example.com"
            )
        )
    }
}