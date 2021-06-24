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
package com.comcast.cdn.traffic_control.traffic_router.shared

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

@JsonIgnoreProperties(ignoreUnknown = true)
class CertificateData {
    @JsonProperty
    private var deliveryservice: String? = null

    @JsonProperty
    private var certificate: Certificate? = null

    @JsonProperty
    private var hostname: String? = null
    fun getDeliveryservice(): String? {
        return deliveryservice
    }

    fun setDeliveryservice(deliveryservice: String?) {
        this.deliveryservice = deliveryservice
    }

    fun getCertificate(): Certificate? {
        return certificate
    }

    fun setCertificate(certificate: Certificate?) {
        this.certificate = certificate
    }

    fun getHostname(): String? {
        return hostname
    }

    fun alias(): String? {
        return getHostname().replaceFirst("\\*\\.".toRegex(), "")
    }

    fun setHostname(hostname: String?) {
        this.hostname = hostname.toLowerCase()
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as CertificateData?
        if (if (deliveryservice != null) deliveryservice != that.deliveryservice else that.deliveryservice != null) return false
        if (if (certificate != null) certificate != that.certificate else that.certificate != null) return false
        return if (hostname != null) hostname == that.hostname else that.hostname == null
    }

    override fun hashCode(): Int {
        var result = if (deliveryservice != null) deliveryservice.hashCode() else 0
        result = 31 * result + if (certificate != null) certificate.hashCode() else 0
        result = 31 * result + if (hostname != null) hostname.hashCode() else 0
        return result
    }
}