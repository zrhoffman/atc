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

import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterNioEndpoint
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import com.comcast.cdn.traffic_control.traffic_router.utils.HttpsProperties
import org.apache.log4j.Logger
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.math.BigInteger
import java.net.InetAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import java.util.function.Consumer

class CertificateRegistry private constructor() {
    private var certificateDataConverter: CertificateDataConverter? = CertificateDataConverter()

    @Volatile
    private var handshakeDataMap: MutableMap<String?, HandshakeData?>? = HashMap()
    private var sslEndpoint: RouterNioEndpoint? = null
    private val previousData: MutableMap<String?, CertificateData?>? = HashMap()
    var defaultAlias: String? = null
    fun getAliases(): MutableList<String?>? {
        return ArrayList(handshakeDataMap.keys)
    }

    fun getHandshakeData(alias: String?): HandshakeData? {
        return handshakeDataMap.get(alias)
    }

    fun getHandshakeData(): MutableMap<String?, HandshakeData?>? {
        return handshakeDataMap
    }

    fun setEndPoint(routerNioEndpoint: RouterNioEndpoint?) {
        sslEndpoint = routerNioEndpoint
    }

    private fun createApiDefaultSsl(): HandshakeData? {
        try {
            val httpsProperties = HttpsProperties().httpsPropertiesMap
            val ks = KeyStore.getInstance("JKS")
            val selfSignedKeystoreFile = httpsProperties["https.certificate.location"]
            if (File(selfSignedKeystoreFile).exists()) {
                val password = httpsProperties["https.password"]
                val readStream: InputStream = FileInputStream(selfSignedKeystoreFile)
                ks.load(readStream, password.toCharArray())
                readStream.close()
                val certs = ks.getCertificateChain(defaultAlias)
                val x509certs: MutableList<X509Certificate?> =
                    ArrayList()
                for (cert in certs) {
                    val cf =
                        CertificateFactory.getInstance("X.509")
                    val bais = ByteArrayInputStream(cert.encoded)
                    val x509cert =
                        cf.generateCertificate(bais) as X509Certificate
                    x509certs.add(x509cert)
                }
                var x509CertsArray: Array<X509Certificate?>? =
                    arrayOfNulls<X509Certificate?>(x509certs.size)
                x509CertsArray = x509certs.toArray(x509CertsArray)
                return HandshakeData(
                    defaultAlias, defaultAlias,
                    x509CertsArray, ks.getKey(defaultAlias, password.toCharArray()) as PrivateKey
                )
            }
        } catch (e: Exception) {
            CertificateRegistry.Companion.log.error("Failed to load default certificate. Received " + e.javaClass + " with message: " + e.message)
            return null
        }
        return null
    }

    private object CertificateRegistryHolder {
        private val DELIVERY_SERVICE_CERTIFICATES: CertificateRegistry? = CertificateRegistry()
    }

    @Synchronized
    fun importCertificateDataList(certificateDataList: MutableList<CertificateData?>?) {
        val changes: MutableMap<String?, HandshakeData?> = HashMap()
        val master: MutableMap<String?, HandshakeData?> = HashMap()

        // find CertificateData which has changed
        for (certificateData in certificateDataList) {
            try {
                val alias = certificateData.alias()
                if (!master.containsKey(alias)) {
                    val handshakeData = certificateDataConverter.toHandshakeData(certificateData)
                    if (handshakeData != null) {
                        master[alias] = handshakeData
                        if (certificateData != previousData.get(alias)) {
                            changes[alias] = handshakeData
                            CertificateRegistry.Companion.log.warn("Imported handshake data with alias $alias")
                        }
                    }
                } else {
                    CertificateRegistry.Companion.log.error(
                        "An TLS certificate already exists in the registry for host: " + alias + " There can be " +
                                "only one!"
                    )
                }
            } catch (e: Exception) {
                CertificateRegistry.Companion.log.error("Failed to import certificate data for delivery service: '" + certificateData.getDeliveryservice() + "', hostname: '" + certificateData.getHostname() + "'")
            }
        }
        // find CertificateData which has been removed
        for (alias in previousData.keys) {
            if (!master.containsKey(alias) && sslEndpoint != null) {
                val hostname = previousData.get(alias).getHostname()
                sslEndpoint.removeSslHostConfig(hostname)
                CertificateRegistry.Companion.log.warn("Removed handshake data with hostname $hostname")
            }
        }

        // store the result for the next import
        previousData.clear()
        for (certificateData in certificateDataList) {
            val alias = certificateData.alias()
            if (!previousData.containsKey(alias) && master.containsKey(alias)) {
                previousData[alias] = certificateData
            }
        }

        // Check to see if a Default cert has been provided by Traffic Ops
        if (!master.containsKey(CertificateRegistry.Companion.DEFAULT_SSL_KEY)) {
            // Check to see if a Default cert has been provided/created previously
            if (handshakeDataMap.containsKey(CertificateRegistry.Companion.DEFAULT_SSL_KEY)) {
                master[CertificateRegistry.Companion.DEFAULT_SSL_KEY] =
                    handshakeDataMap.get(CertificateRegistry.Companion.DEFAULT_SSL_KEY)
            } else {
                // create a new default certificate
                val defaultHd: HandshakeData = CertificateRegistry.Companion.createDefaultSsl()
                if (defaultHd == null) {
                    CertificateRegistry.Companion.log.error(
                        "Failed to initialize the CertificateRegistry because of a problem with the 'default' " +
                                "certificate. Returning the Certificate Registry without a default."
                    )
                    return
                }
                master[CertificateRegistry.Companion.DEFAULT_SSL_KEY] = defaultHd
            }
        }
        if (!master.containsKey(defaultAlias)) {
            if (handshakeDataMap.containsKey(defaultAlias)) {
                master[defaultAlias] = handshakeDataMap.get(defaultAlias)
            } else {
                val apiDefault = createApiDefaultSsl()
                if (apiDefault == null) {
                    CertificateRegistry.Companion.log.error("Failed to initialize the API Default certificate.")
                } else {
                    master[apiDefault.hostname] = apiDefault
                }
            }
        }
        handshakeDataMap = master

        // This will update the SSLHostConfig objects stored in the server
        // if any of those updates fail then we need to be sure to remove them
        // from the previousData list so that we will try to update them again
        // next time we import certificates
        if (sslEndpoint != null && !changes.isEmpty()) {
            val failedUpdates = sslEndpoint.reloadSSLHosts(changes)
            failedUpdates.forEach(Consumer { alias: String? -> previousData.remove(alias) })
        }
    }

    fun getCertificateDataConverter(): CertificateDataConverter? {
        return certificateDataConverter
    }

    fun setCertificateDataConverter(certificateDataConverter: CertificateDataConverter?) {
        this.certificateDataConverter = certificateDataConverter
    }

    companion object {
        val DEFAULT_SSL_KEY: String? = "default.invalid"
        private val log = Logger.getLogger(CertificateRegistry::class.java)
        fun getInstance(): CertificateRegistry? {
            return CertificateRegistryHolder.DELIVERY_SERVICE_CERTIFICATES
        }

        private fun createDefaultSsl(): HandshakeData? {
            return try {
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                val keyPair = keyPairGenerator.generateKeyPair()

                //Generate self signed certificate
                val chain = arrayOfNulls<X509Certificate?>(1)

                // Select provider
                Security.addProvider(BouncyCastleProvider())

                // Generate cert details
                val now = System.currentTimeMillis()
                val startDate = Date(System.currentTimeMillis())
                val dnName = X500Name(
                    "C=US; ST=CO; L=Denver; " +
                            "O=Apache Traffic Control; OU=Apache Foundation; OU=Hosted by Traffic Control; " +
                            "OU=CDNDefault; CN=" + CertificateRegistry.Companion.DEFAULT_SSL_KEY
                )
                val certSerialNumber = BigInteger(java.lang.Long.toString(now))
                val calendar = Calendar.getInstance()
                calendar.time = startDate
                calendar.add(Calendar.YEAR, 3)
                val endDate = calendar.time

                // Build certificate
                val contentSigner = JcaContentSignerBuilder("SHA1WithRSA").build(keyPair.private)
                val certBuilder =
                    JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.public)

                // Attach extensions
                certBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
                certBuilder.addExtension(
                    Extension.keyUsage,
                    true,
                    KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment or KeyUsage.keyCertSign)
                )
                certBuilder.addExtension(
                    Extension.extendedKeyUsage, true, ExtendedKeyUsage(
                        arrayOf(
                            KeyPurposeId.id_kp_clientAuth,
                            KeyPurposeId.id_kp_serverAuth
                        )
                    )
                )

                // Generate final certificate
                val certHolder = certBuilder.build(contentSigner)
                val converter = JcaX509CertificateConverter()
                converter.setProvider(BouncyCastleProvider())
                chain[0] = converter.getCertificate(certHolder)
                HandshakeData(
                    CertificateRegistry.Companion.DEFAULT_SSL_KEY,
                    CertificateRegistry.Companion.DEFAULT_SSL_KEY,
                    chain,
                    keyPair.private
                )
            } catch (e: Exception) {
                CertificateRegistry.Companion.log.error("Could not generate the default certificate: " + e.message, e)
                null
            }
        }
    }

    // Recommended Singleton Pattern implementation
    // https://community.oracle.com/docs/DOC-918906
    init {
        try {
            defaultAlias = InetAddress.getLocalHost().hostName
        } catch (e: Exception) {
            CertificateRegistry.Companion.log.error("Error getting hostname")
        }
    }
}