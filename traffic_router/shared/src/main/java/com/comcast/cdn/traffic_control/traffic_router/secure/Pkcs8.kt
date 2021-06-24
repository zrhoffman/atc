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

import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs8
import org.apache.log4j.Logger
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

class Pkcs8(data: String?) : Pkcs(data) {
    override fun getHeader(): String? {
        return HEADER
    }

    override fun getFooter(): String? {
        return FOOTER
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    override fun decodeKeySpec(data: String?): KeySpec? {
        try {
            return PKCS8EncodedKeySpec(Base64.getDecoder().decode(data.toByteArray()))
        } catch (e: Exception) {
            LOGGER.error("Failed to create PKCS8 Encoded Key Spec " + e.javaClass.canonicalName + ": " + e.message, e)
        }
        return null
    }

    companion object {
        private val LOGGER = Logger.getLogger(Pkcs8::class.java)
        val HEADER: String? = "-----BEGIN PRIVATE KEY-----"
        val FOOTER: String? = "-----END PRIVATE KEY-----"
    }
}