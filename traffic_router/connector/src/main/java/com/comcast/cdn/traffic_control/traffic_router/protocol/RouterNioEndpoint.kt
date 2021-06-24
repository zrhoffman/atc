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

import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterNioEndpoint
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry
import com.comcast.cdn.traffic_control.traffic_router.secure.HandshakeData
import com.comcast.cdn.traffic_control.traffic_router.secure.KeyManager
import org.apache.log4j.Logger
import org.apache.tomcat.jni.SSL
import org.apache.tomcat.util.net.NioChannel
import org.apache.tomcat.util.net.NioEndpoint
import org.apache.tomcat.util.net.SSLHostConfig
import org.apache.tomcat.util.net.SSLHostConfigCertificate
import org.apache.tomcat.util.net.SocketEvent
import org.apache.tomcat.util.net.SocketProcessorBase
import org.apache.tomcat.util.net.SocketWrapperBase
import java.util.function.Consumer

class RouterNioEndpoint : NioEndpoint() {
    private var protocols: String? = null

    // Grabs the aliases from our custom certificate registry, creates a sslHostConfig for them
    // and adds the newly created config to the list of sslHostConfigs.  We also remove the default config
    // since it won't be found in our registry.  This allows OpenSSL to start successfully and serve our
    // certificates.  When we are done we call the parent classes initialiseSsl.
    @Throws(Exception::class)
    override fun initialiseSsl() {
        if (isSSLEnabled) {
            destroySsl()
            sslHostConfigs.clear()
            val keyManager = KeyManager()
            val certificateRegistry = keyManager.certificateRegistry
            replaceSSLHosts(certificateRegistry.handshakeData)

            //Now let initialiseSsl do it's thing.
            super.initialiseSsl()
            certificateRegistry.setEndPoint(this)
        }
    }

    @Synchronized
    private fun replaceSSLHosts(sslHostsData: MutableMap<String?, HandshakeData?>?): MutableList<String?>? {
        val aliases = sslHostsData.keys
        var lastHostName = ""
        val failedUpdates: MutableList<String?> = ArrayList()
        for (alias in aliases) {
            val sslHostConfig = SSLHostConfig()
            val cert = SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.RSA)
            sslHostConfig.hostName = sslHostsData.get(alias).getHostname()
            cert.certificateKeyAlias = alias
            sslHostConfig.addCertificate(cert)
            sslHostConfig.setProtocols(if (protocols != null) protocols else "all")
            sslHostConfig.sslProtocol = sslHostConfig.sslProtocol
            sslHostConfig.setCertificateVerification("none")
            RouterNioEndpoint.Companion.LOGGER.info("sslHostConfig: " + sslHostConfig.hostName + " " + sslHostConfig.truststoreAlgorithm)
            if (sslHostConfig.hostName != lastHostName) {
                try {
                    addSslHostConfig(sslHostConfig, true)
                } catch (fubar: Exception) {
                    RouterNioEndpoint.Companion.LOGGER.error(
                        "In RouterNioEndpoint.replaceSSLHosts, sslHostConfig and certs did not get replaced " +
                                "for host: " + sslHostConfig.hostName + ", because of execption - " + fubar.toString()
                    )
                    failedUpdates.add(alias)
                }
                lastHostName = sslHostConfig.hostName
            }
            if (CertificateRegistry.Companion.DEFAULT_SSL_KEY == alias && !failedUpdates.contains(alias)) {
                // One of the configs must be set as the default
                defaultSSLHostConfigName = sslHostConfig.hostName
            }
        }
        return failedUpdates
    }

    @Synchronized
    fun reloadSSLHosts(cr: MutableMap<String?, HandshakeData?>?): MutableList<String?>? {
        val failedUpdates = replaceSSLHosts(cr)
        if (!failedUpdates.isEmpty()) {
            failedUpdates.forEach(Consumer { alias: String? -> cr.remove(alias) })
        }
        val failedContextUpdates: MutableList<String?> = ArrayList()
        for (alias in cr.keys) {
            try {
                val data = cr.get(alias)
                val sslHostConfig = sslHostConfigs[data.getHostname()]
                sslHostConfig.setSslProtocol(sslHostConfig.getSslProtocol())
                createSSLContext(sslHostConfig)
            } catch (rfubar: Exception) {
                RouterNioEndpoint.Companion.LOGGER.error(
                    "In RouterNioEndpoint could not create new SSLContext for cert " + alias +
                            " because of exception: " + rfubar.toString()
                )
                failedContextUpdates.add(alias)
            }
        }
        if (!failedContextUpdates.isEmpty()) {
            failedUpdates.addAll(failedContextUpdates)
        }
        return failedUpdates
    }

    override fun getSSLHostConfig(sniHostName: String?): SSLHostConfig? {
        return super.getSSLHostConfig(sniHostName?.toLowerCase())
    }

    override fun createSocketProcessor(
        socketWrapper: SocketWrapperBase<NioChannel?>?, event: SocketEvent?
    ): SocketProcessorBase<NioChannel?>? {
        return RouterSocketProcessor(socketWrapper, event)
    }

    /**
     * This class is the equivalent of the Worker, but will simply use in an
     * external Executor thread pool.
     */
    protected inner class RouterSocketProcessor(socketWrapper: SocketWrapperBase<NioChannel?>?, event: SocketEvent?) :
        SocketProcessor(socketWrapper, event) {
        /* This override has been added as a temporary hack to resolve an issue in Tomcat.
		Once the issue has been corrected in Tomcat then this can be removed. The
		'SSL.getLastErrorNumber()' removes an unwanted error condition from the error stack
		in those cases where some error condition has caused the socket to get closed and
		then the processor was put back on the processor stack for reuse in a future connection.
		*/
        override fun doRun() {
            val localWrapper = socketWrapper
            val socket = localWrapper.socket
            super.doRun()
            if (!socket.isOpen) {
                SSL.getLastErrorNumber()
            }
        }
    }

    fun getProtocols(): String? {
        return protocols
    }

    fun setProtocols(protocols: String?) {
        this.protocols = protocols
    }

    companion object {
        private val LOGGER = Logger.getLogger(RouterNioEndpoint::class.java)
    }
}