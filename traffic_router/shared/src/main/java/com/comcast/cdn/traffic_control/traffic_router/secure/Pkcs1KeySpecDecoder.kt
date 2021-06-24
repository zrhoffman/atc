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

import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs1KeySpecDecoder
import org.apache.log4j.Logger
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

class Pkcs1KeySpecDecoder {
    @Throws(IOException::class, GeneralSecurityException::class)
    fun decode(data: String?): KeySpec? {
        val pemData: String =
            data.replace(Pkcs1.Companion.HEADER.toRegex(), "").replace(Pkcs1.Companion.FOOTER.toRegex(), "")
                .replace("\\s".toRegex(), "")
        val asn1Sequence = ASN1Sequence.getInstance(Base64.getDecoder().decode(pemData))
        val sequenceLength = asn1Sequence.toArray().size
        if (sequenceLength != PUBLIC_SEQUENCE_LENGTH && sequenceLength != PRIVATE_SEQUENCE_LENGTH) {
            throw GeneralSecurityException("Invalid PKCS1 key! Missing Key Data, incorrect number of DER values for either public or private key")
        }
        if (asn1Sequence.toArray().size == PUBLIC_SEQUENCE_LENGTH) {
            val asn1Parser = asn1Sequence.parser()
            val n = (asn1Parser.readObject() as ASN1Integer).value
            val e = (asn1Parser.readObject() as ASN1Integer).value
            return RSAPublicKeySpec(n, e)
        }

        // man 3 rsa
        // -- or --
        // http://linux.die.net/man/3/rsa
        //Convert to PKCS8 since OpenSSL doesn't support PKCS1.  This works because of the BouncyCastle security provider.
        try {
            return PKCS8EncodedKeySpec(Base64.getDecoder().decode(data.toByteArray()))
        } catch (e: Exception) {
            LOGGER.error(
                "Error converting to PKCS8 Encoded Key Spec " + e.javaClass.canonicalName + ": " + e.message,
                e
            )
        }
        return null
    }

    companion object {
        // https://tools.ietf.org/html/rfc3447#appendix-A.1.1
        const val PRIVATE_SEQUENCE_LENGTH = 9
        const val PUBLIC_SEQUENCE_LENGTH = 2
        private val LOGGER = Logger.getLogger(Pkcs1KeySpecDecoder::class.java)
    }
}