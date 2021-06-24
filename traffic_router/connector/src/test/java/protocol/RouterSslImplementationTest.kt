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
package protocol

import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterSslImplementation
import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterSslUtil
import org.apache.tomcat.util.net.SSLHostConfig
import org.apache.tomcat.util.net.SSLHostConfigCertificate
import org.apache.tomcat.util.net.SSLSupport
import org.apache.tomcat.util.net.SSLUtil
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import javax.net.ssl.SSLSession

@RunWith(PowerMockRunner::class)
@PrepareForTest(RouterSslImplementation::class, SSLHostConfigCertificate::class, RouterSslUtil::class)
class RouterSslImplementationTest {
    var sslSession = PowerMockito.mock(SSLSession::class.java)
    var sslHostConfig = PowerMockito.mock(SSLHostConfig::class.java)
    var type = PowerMockito.mock(
        SSLHostConfigCertificate.Type::class.java
    )
    var sslHostConfigCertificate: SSLHostConfigCertificate? = SSLHostConfigCertificate(sslHostConfig, type)
    var sslutil = PowerMockito.mock(RouterSslUtil::class.java)

    @Test
    @Throws(Exception::class)
    fun itReturnsSSLSupport() {
        MatcherAssert.assertThat(
            RouterSslImplementation().getSSLSupport(sslSession), Matchers.instanceOf(
                SSLSupport::class.java
            )
        )
    }

    @Test
    @Throws(Exception::class)
    fun itReturnsSSLUtil() {
        PowerMockito.whenNew(RouterSslUtil::class.java).withArguments(sslHostConfigCertificate).thenReturn(sslutil)
        MatcherAssert.assertThat(
            RouterSslImplementation().getSSLUtil(sslHostConfigCertificate), Matchers.instanceOf(
                SSLUtil::class.java
            )
        )
    }

    @Test
    @Throws(Exception::class)
    fun itRegistersSSLHostConfigs() {
    }

    @Before
    fun before() {
    }
}