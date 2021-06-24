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

import com.comcast.cdn.traffic_control.traffic_router.protocol.LanguidNioProtocol
import org.apache.coyote.http11.AbstractHttp11JsseProtocol
import org.apache.juli.logging.Log
import org.apache.juli.logging.LogFactory
import org.apache.tomcat.util.net.NioChannel
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class LanguidNioProtocol : AbstractHttp11JsseProtocol<NioChannel?>(RouterNioEndpoint()), RouterProtocolHandler {
    private var ready = false
    private var initialized = false
    private var mbeanPath: String? = null
    private var readyAttribute: String? = null
    private var portAttribute: String? = null

    companion object {
        protected var log = LogFactory.getLog(LanguidNioProtocol::class.java)

        //add BouncyCastle provider to support converting PKCS1 to PKCS8 since OpenSSL does not support PKCS1
        //TODO:  Figure out if we can convert from PKCS1 to PKCS8 with out BC
        init {
            LanguidNioProtocol.Companion.log.warn("Adding BouncyCastle provider")
            Security.addProvider(BouncyCastleProvider())
        }
    }

    override fun setSslImplementationName(sslClassName: String?) {
        try {
            Class.forName(sslClassName)
            LanguidNioProtocol.Companion.log.info("setSslImplementation: $sslClassName")
            super.setSslImplementationName(sslClassName)
        } catch (e: ClassNotFoundException) {
            LanguidNioProtocol.Companion.log.error("LanguidNIOProtocol: Failed to set SSL implementation to $sslClassName class was not found, defaulting to OpenSSL")
        }
    }

    @Throws(Exception::class)
    override fun init() {
        if (!isReady) {
            LanguidNioProtocol.Companion.log.info("Init called; creating thread to monitor the state of Traffic Router")
            LanguidPoller(this).start()
            return
        }
        LanguidNioProtocol.Companion.log.info("Traffic Router SSL Protocol is ready; calling super.init()")
        endpoint.bindOnInit = false
        super.init()
        isInitialized = true
    }

    @Throws(Exception::class)
    override fun start() {
        LanguidNioProtocol.Companion.log.info("LanguidNioProtocol Handler Start called; waiting for initialization to occur")
        while (!isInitialized) {
            try {
                Thread.sleep(100)
            } catch (e: InterruptedException) {
                LanguidNioProtocol.Companion.log.info("interrupted waiting for initialization")
            }
        }
        LanguidNioProtocol.Companion.log.info("LanguidNioProtocol Handler Initialization complete; calling super.start()")
        super.start()
    }

    override fun isReady(): Boolean {
        return ready
    }

    override fun setReady(isReady: Boolean) {
        ready = isReady
    }

    override fun isInitialized(): Boolean {
        return initialized
    }

    override fun setInitialized(isInitialized: Boolean) {
        initialized = isInitialized
    }

    override fun getMbeanPath(): String? {
        return mbeanPath
    }

    override fun setMbeanPath(mbeanPath: String?) {
        this.mbeanPath = mbeanPath
    }

    override fun getReadyAttribute(): String? {
        return readyAttribute
    }

    override fun setReadyAttribute(readyAttribute: String?) {
        this.readyAttribute = readyAttribute
    }

    override fun getPortAttribute(): String? {
        return portAttribute
    }

    override fun setPortAttribute(portAttribute: String?) {
        this.portAttribute = portAttribute
    }

    override fun getSslImplementationShortName(): String? {
        return "openssl"
    }

    override fun getNamePrefix(): String? {
        return if (isSSLEnabled) {
            "https-$sslImplementationShortName-nio"
        } else {
            "http-nio"
        }
    }

    override fun getLog(): Log? {
        return LanguidNioProtocol.Companion.log
    }

    init {
        LanguidNioProtocol.Companion.log.warn("Serving wildcard certs for multiple domains")
    }
}