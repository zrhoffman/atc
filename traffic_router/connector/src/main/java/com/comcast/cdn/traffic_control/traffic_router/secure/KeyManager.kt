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
package com.comcast.cdn.traffic_control.traffic_router.secure

import com.comcast.cdn.traffic_control.traffic_router.secure.KeyManager
import org.apache.log4j.Logger
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.stream.Collectors
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509KeyManager

// Uses the in memory CertificateRegistry to provide dynamic key and certificate management for the router
// The provided default implementation does not allow for the key store to change state
// once the JVM loads the default classes.
class KeyManager : X509ExtendedKeyManager(), X509KeyManager {
    private val certificateRegistry: CertificateRegistry? = CertificateRegistry.Companion.getInstance()

    // To date this method is not getting exercised while running the router
    override fun chooseClientAlias(strings: Array<String?>?, principals: Array<Principal?>?, socket: Socket?): String? {
        throw UnsupportedOperationException("Traffic Router KeyManager does not support choosing Client Alias")
    }

    // To date this method is not getting exercised while running the router
    override fun getServerAliases(s: String?, principals: Array<Principal?>?): Array<String?>? {
        return certificateRegistry.getAliases().toTypedArray()
    }

    // To date this method is not getting exercised while running the router
    override fun getClientAliases(s: String?, principals: Array<Principal?>?): Array<String?>? {
        throw UnsupportedOperationException("Traffic Router KeyManager does not support getting a list of Client Aliases")
    }

    override fun chooseEngineServerAlias(keyType: String?, issuers: Array<Principal?>?, engine: SSLEngine?): String? {
        if (keyType == null) {
            return null
        }
        val sslSession = engine.getHandshakeSession() as ExtendedSSLSession
        return chooseServerAlias(sslSession)
    }

    override fun chooseServerAlias(keyType: String?, principals: Array<Principal?>?, socket: Socket?): String? {
        if (keyType == null || socket == null) {
            return null
        }
        val sslSocket = socket as SSLSocket?
        val sslSession = sslSocket.getHandshakeSession() as ExtendedSSLSession
        return chooseServerAlias(sslSession)
    }

    private fun chooseServerAlias(sslSession: ExtendedSSLSession?): String? {
        val requestedNames = sslSession.getRequestedServerNames()
        val stringBuilder = StringBuilder()
        for (requestedName in requestedNames) {
            if (stringBuilder.length > 0) {
                stringBuilder.append(", ")
            }
            val sniString = String(requestedName.encoded)
            stringBuilder.append(sniString)
            val partialAliasMatches =
                certificateRegistry.getAliases().stream().filter { s: String? -> sniString.contains(s) }
                    .collect(Collectors.toList())
            var alias = partialAliasMatches.stream().filter { cs: String? -> sniString.contentEquals(cs) }.findFirst()
            if (alias.isPresent) {
                return alias.get()
            }

            // Not an exact match, some of the aliases may have had the leading zone removed
            val sniStringTrimmed = sniString.substring(sniString.indexOf('.') + 1)
            alias =
                partialAliasMatches.stream().filter { cs: String? -> sniStringTrimmed.contentEquals(cs) }.findFirst()
            if (alias.isPresent) {
                return alias.get()
            }
        }
        if (stringBuilder.length > 0) {
            KeyManager.Companion.log.warn("KeyManager: No certificate registry aliases matching $stringBuilder")
        } else {
            KeyManager.Companion.log.warn("KeyManager: Client " + sslSession.getPeerHost() + " did not send any Server Name Indicators")
        }
        return null
    }

    override fun getCertificateChain(alias: String?): Array<X509Certificate?>? {
        val handshakeData = certificateRegistry.getHandshakeData(alias)
        if (handshakeData != null) {
            return handshakeData.certificateChain
        }
        KeyManager.Companion.log.error("KeyManager: No certificate chain for alias $alias")
        return null
    }

    override fun getPrivateKey(alias: String?): PrivateKey? {
        val handshakeData = certificateRegistry.getHandshakeData(alias)
        if (handshakeData != null) {
            return handshakeData.privateKey
        }
        KeyManager.Companion.log.error("KeyManager: No private key for alias $alias")
        return null
    }

    fun getCertificateRegistry(): CertificateRegistry? {
        return certificateRegistry
    }

    companion object {
        private val log = Logger.getLogger(KeyManager::class.java)
    }
}