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

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.spec.KeySpec

class Pkcs1 : Pkcs {
    constructor(data: String?) : super(data) {}
    constructor(privateData: String?, publicData: String?) : super(privateData, publicData) {}

    override fun getHeader(): String? {
        return HEADER
    }

    override fun getFooter(): String? {
        return FOOTER
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    override fun decodeKeySpec(data: String?): KeySpec? {
        return Pkcs1KeySpecDecoder().decode(data)
    }

    companion object {
        val HEADER: String? = "-----BEGIN RSA PRIVATE KEY-----"
        val FOOTER: String? = "-----END RSA PRIVATE KEY-----"
    }
}