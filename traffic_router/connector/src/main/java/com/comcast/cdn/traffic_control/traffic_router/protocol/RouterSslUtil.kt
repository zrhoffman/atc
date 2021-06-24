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
package com.comcast.cdn.traffic_control.traffic_router.protocol

import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterSslUtil
import org.apache.juli.logging.Log
import org.apache.juli.logging.LogFactory
import org.apache.tomcat.util.net.SSLContext
import org.apache.tomcat.util.net.SSLHostConfigCertificate
import org.apache.tomcat.util.net.SSLUtilBase
import org.apache.tomcat.util.net.openssl.OpenSSLContext
import org.apache.tomcat.util.net.openssl.OpenSSLEngine
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLSessionContext
import javax.net.ssl.TrustManager

class RouterSslUtil(certificate: SSLHostConfigCertificate?) : SSLUtilBase(certificate) {
    override fun getLog(): Log? {
        return RouterSslUtil.Companion.log
    }

    override fun getImplementedProtocols(): MutableSet<String?>? {
        return OpenSSLEngine.IMPLEMENTED_PROTOCOLS_SET
    }

    override fun getImplementedCiphers(): MutableSet<String?>? {
        return OpenSSLEngine.AVAILABLE_CIPHER_SUITES
    }

    @Throws(Exception::class)
    public override fun createSSLContextInternal(negotiableProtocols: MutableList<String?>?): SSLContext? {
        return OpenSSLContext(certificate, negotiableProtocols)
    }

    public override fun isTls13RenegAuthAvailable(): Boolean {
        // As per the Tomcat 8.5.57 source, this should be false for JSSE, and true for openSSL implementations.
        return true
    }

    @Throws(Exception::class)
    override fun getKeyManagers(): Array<KeyManager?>? {
        return arrayOf(com.comcast.cdn.traffic_control.traffic_router.secure.KeyManager())
    }

    @Throws(Exception::class)
    override fun getTrustManagers(): Array<TrustManager?>? {
        return null
    }

    override fun configureSessionContext(sslSessionContext: SSLSessionContext?) {}

    companion object {
        private val log = LogFactory.getLog(RouterSslUtil::class.java)
    }
}