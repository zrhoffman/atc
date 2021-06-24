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

import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataConverter
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import org.apache.log4j.Logger
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
import java.math.BigInteger
import java.security.PrivateKey
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec

class CertificateDataConverter {
    private var privateKeyDecoder: PrivateKeyDecoder? = PrivateKeyDecoder()
    private var certificateDecoder: CertificateDecoder? = CertificateDecoder()
    fun toHandshakeData(certificateData: CertificateData?): HandshakeData? {
        try {
            val privateKey = privateKeyDecoder.decode(certificateData.getCertificate().key)
            val encodedCertificates = certificateDecoder.doubleDecode(certificateData.getCertificate().crt)
            val x509Chain: MutableList<X509Certificate?> = ArrayList()
            var hostMatch = false
            var modMatch = false
            for (encodedCertificate in encodedCertificates) {
                val certificate = certificateDecoder.toCertificate(encodedCertificate)
                certificate.checkValidity()
                if (!hostMatch && verifySubject(certificate, certificateData.alias())) {
                    hostMatch = true
                }
                if (!modMatch && verifyModulus(privateKey, certificate)) {
                    modMatch = true
                }
                x509Chain.add(certificate)
            }
            if (hostMatch && modMatch) {
                return HandshakeData(
                    certificateData.getDeliveryservice(), certificateData.getHostname(),
                    x509Chain.toTypedArray(), privateKey
                )
            } else if (!hostMatch) {
                CertificateDataConverter.Companion.log.warn("Service name doesn't match the subject of the certificate = " + certificateData.getHostname())
            } else if (!modMatch) {
                CertificateDataConverter.Companion.log.warn("Modulus of the private key does not match the public key modulus for certificate host: " + certificateData.getHostname())
            }
        } catch (er: CertificateNotYetValidException) {
            CertificateDataConverter.Companion.log.warn(
                "Failed to convert certificate data for delivery service = " + certificateData.getHostname()
                        + ", because the certificate is not valid yet. This certificate will not be used by " +
                        "Traffic Router."
            )
        } catch (ex: CertificateExpiredException) {
            CertificateDataConverter.Companion.log.warn(
                "Failed to convert certificate data for delivery service = " + certificateData.getHostname()
                        + ", because the certificate has expired. This certificate will not be used by Traffic Router."
            )
        } catch (e: Exception) {
            CertificateDataConverter.Companion.log.warn(
                "Failed to convert certificate data (delivery service = " + certificateData.getDeliveryservice()
                        + ", hostname = " + certificateData.getHostname() + ") from traffic ops to handshake data! This " +
                        "certificate will not be used by Traffic Router. "
                        + e.javaClass.simpleName + ": " + e.message, e
            )
        }
        return null
    }

    fun verifySubject(certificate: X509Certificate?, hostAlias: String?): Boolean {
        val host = certificate.getSubjectDN().name
        if (hostCompare(hostAlias, host)) {
            return true
        }
        try {
            // This approach is probably the only one that is JDK independent
            if (certificate.getSubjectAlternativeNames() != null) {
                for (altName in certificate.getSubjectAlternativeNames()) {
                    if (hostCompare(hostAlias, altName[1] as String?)) {
                        return true
                    }
                }
            }
        } catch (e: Exception) {
            CertificateDataConverter.Companion.log.error(
                "Encountered an error while validating the certificate subject for service: " + hostAlias + ", " +
                        "error: " + e.javaClass.simpleName + ": " + e.message, e
            )
            return false
        }
        return false
    }

    private fun hostCompare(hostAlias: String?, subject: String?): Boolean {
        if (hostAlias.contains(subject) || subject.contains(hostAlias)) {
            return true
        }

        // Parse subjectName out of Common Name
        // If no CN= present, then subjectName is a SAN and needs only wildcard removal
        var subjectName = subject
        if (subjectName.contains("CN=")) {
            val chopped: Array<String?> = subjectName.split("CN=".toRegex(), 2).toTypedArray()
            if (chopped != null && chopped.size > 1) {
                val chop = chopped[1]
                subjectName = chop.split(",".toRegex(), 2).toTypedArray()[0]
            }
        }
        subjectName = subjectName.replaceFirst("\\*\\.".toRegex(), ".")
        return if (subjectName.length > 0 && (hostAlias.contains(subjectName) || subjectName.contains(hostAlias))) {
            true
        } else false
    }

    fun verifyModulus(privateKey: PrivateKey?, certificate: X509Certificate?): Boolean {
        var privModulus: BigInteger? = null
        privModulus = if (privateKey is BCRSAPrivateCrtKey) {
            (privateKey as BCRSAPrivateCrtKey?).getModulus()
        } else if (privateKey is RSAPrivateCrtKeySpec) {
            (privateKey as RSAPrivateCrtKeySpec?).getModulus()
        } else {
            return false
        }
        var pubModulus: BigInteger? = null
        val publicKey = certificate.getPublicKey()
        if (publicKey is RSAPublicKeySpec) {
            pubModulus = (publicKey as RSAPublicKeySpec).modulus
        } else {
            val keyparts: Array<String?> =
                publicKey.toString().split(System.getProperty("line.separator").toRegex()).toTypedArray()
            for (part in keyparts) {
                val start = part.indexOf("modulus: ") + 9
                if (start < 9) {
                    continue
                } else {
                    pubModulus = BigInteger(part.substring(start))
                    break
                }
            }
        }
        return if (privModulus == pubModulus) {
            true
        } else false
    }

    fun getPrivateKeyDecoder(): PrivateKeyDecoder? {
        return privateKeyDecoder
    }

    fun setPrivateKeyDecoder(privateKeyDecoder: PrivateKeyDecoder?) {
        this.privateKeyDecoder = privateKeyDecoder
    }

    fun getCertificateDecoder(): CertificateDecoder? {
        return certificateDecoder
    }

    fun setCertificateDecoder(certificateDecoder: CertificateDecoder?) {
        this.certificateDecoder = certificateDecoder
    }

    companion object {
        private val log = Logger.getLogger(CertificateDataConverter::class.java)
    }
}