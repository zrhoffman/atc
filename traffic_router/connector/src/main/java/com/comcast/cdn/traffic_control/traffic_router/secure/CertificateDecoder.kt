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

import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDecoder
import org.apache.log4j.Logger
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

class CertificateDecoder {
    fun doubleDecode(encoded: String?): MutableList<String?>? {
        val decodedBytes = Base64.getMimeDecoder().decode(encoded.toByteArray())
        val encodedPemItems: MutableList<String?> = ArrayList()
        val lines: Array<String?> = String(decodedBytes).split("\\r?\\n".toRegex()).toTypedArray()
        val builder = StringBuilder()
        for (line in lines) {
            builder.append(line)
            if (line.startsWith(CertificateDecoder.Companion.PEM_FOOTER_PREFIX)) {
                encodedPemItems.add(builder.toString())
                builder.setLength(0)
            }
        }
        if (encodedPemItems.isEmpty()) {
            if (builder.length == 0) {
                CertificateDecoder.Companion.log.warn("Failed base64 decoding")
            } else {
                encodedPemItems.add(builder.toString())
            }
        }
        return encodedPemItems
    }

    fun toCertificate(encodedCertificate: String?): X509Certificate? {
        val encodedBytes: ByteArray = Base64.getDecoder().decode(
            encodedCertificate.replace(CertificateDecoder.Companion.CRT_HEADER.toRegex(), "")
                .replace(CertificateDecoder.Companion.CRT_FOOTER.toRegex(), "")
        )
        try {
            ByteArrayInputStream(encodedBytes).use { stream ->
                return CertificateFactory.getInstance("X.509").generateCertificate(stream) as X509Certificate
            }
        } catch (e: Exception) {
            val message = "Failed to decode certificate data to X509! " + e.javaClass.simpleName + ": " + e.message
            CertificateDecoder.Companion.log.error(message, e)
            throw RuntimeException(message, e)
        }
    }

    companion object {
        private val log = Logger.getLogger(CertificateDecoder::class.java)
        private val CRT_HEADER: String? = "-----BEGIN CERTIFICATE-----"
        private val CRT_FOOTER: String? = "-----END CERTIFICATE-----"
        private val PEM_FOOTER_PREFIX: String? = "-----END"
    }
}