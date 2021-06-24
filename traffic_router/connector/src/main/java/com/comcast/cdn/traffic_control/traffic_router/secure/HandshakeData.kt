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

import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.Objects

class HandshakeData(
    private val deliveryService: String?,
    private val hostname: String?,
    private val certificateChain: Array<X509Certificate?>?,
    private var privateKey: PrivateKey?
) {
    fun getDeliveryService(): String? {
        return deliveryService
    }

    fun getHostname(): String? {
        return hostname
    }

    fun getCertificateChain(): Array<X509Certificate?>? {
        return certificateChain
    }

    fun getPrivateKey(): PrivateKey? {
        return privateKey
    }

    fun setPrivateKey(privateKey: PrivateKey?) {
        this.privateKey = privateKey
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o !is HandshakeData) {
            return false
        }
        val that = o as HandshakeData?
        return deliveryService == that.deliveryService &&
                hostname == that.hostname &&
                Arrays.equals(certificateChain, that.certificateChain) &&
                privateKey == that.privateKey
    }

    override fun hashCode(): Int {
        var result = Objects.hash(deliveryService, hostname, privateKey)
        result = 31 * result + Arrays.hashCode(certificateChain)
        return result
    }
}