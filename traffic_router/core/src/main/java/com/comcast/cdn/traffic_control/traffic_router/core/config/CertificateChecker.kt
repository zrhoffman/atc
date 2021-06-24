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
package com.comcast.cdn.traffic_control.traffic_router.core.config

import com.comcast.cdn.traffic_control.traffic_router.core.config.CertificateChecker
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger

class CertificateChecker {
    fun getDeliveryServiceType(deliveryServiceJson: JsonNode?): String? {
        val matchsets = deliveryServiceJson.get("matchsets")
        for (matchset in matchsets) {
            if (matchset == null) {
                continue
            }
            val deliveryServiceType: String = optString(matchset, "protocol")
            if (!deliveryServiceType.isEmpty()) {
                return deliveryServiceType
            }
        }
        return null
    }

    fun certificatesAreValid(
        certificateDataList: MutableList<CertificateData?>?,
        deliveryServicesJson: JsonNode?
    ): Boolean {
        val deliveryServiceIdIter = deliveryServicesJson.fieldNames()
        var invalidConfig = false
        while (deliveryServiceIdIter.hasNext()) {
            if (!deliveryServiceHasValidCertificates(
                    certificateDataList,
                    deliveryServicesJson,
                    deliveryServiceIdIter.next()
                )
            ) {
                invalidConfig =
                    true // individual DS errors are logged when deliveryServiceHasValidCertificates() is called
            }
        }
        return if (invalidConfig) {
            false
        } else true
    }

    fun hasCertificate(certificateDataList: MutableList<CertificateData?>?, deliveryServiceId: String?): Boolean {
        return certificateDataList.stream()
            .filter { cd: CertificateData? -> cd.getDeliveryservice() == deliveryServiceId }
            .findFirst()
            .isPresent
    }

    private fun deliveryServiceHasValidCertificates(
        certificateDataList: MutableList<CertificateData?>?,
        deliveryServicesJson: JsonNode?,
        deliveryServiceId: String?
    ): Boolean {
        val deliveryServiceJson = deliveryServicesJson.get(deliveryServiceId)
        val protocolJson = deliveryServiceJson["protocol"]
        if (!supportsHttps(deliveryServiceJson, protocolJson)) {
            return true
        }
        val domains = deliveryServiceJson["domains"]
        if (domains == null) {
            CertificateChecker.Companion.LOGGER.warn("Delivery Service $deliveryServiceId is not configured with any domains!")
            return true
        }
        if (domains.size() == 0) {
            return true
        }
        for (domain in domains) {
            val domainStr = domain.asText("").replace("^\\*\\.".toRegex(), "")
            if (domainStr == null || domainStr.isEmpty()) {
                continue
            }
            for (certificateData in certificateDataList) {
                val certificateDeliveryServiceId = certificateData.getDeliveryservice()
                if (deliveryServiceId == null || deliveryServiceId == "") {
                    CertificateChecker.Companion.LOGGER.error("Delivery Service name is blank for hostname '" + certificateData.getHostname() + "', skipping.")
                } else if (certificateDeliveryServiceId != null && deliveryServiceId != null && certificateDeliveryServiceId == deliveryServiceId) {
                    CertificateChecker.Companion.LOGGER.debug("Delivery Service $deliveryServiceId has certificate data for https")
                    return true
                }
            }
            CertificateChecker.Companion.LOGGER.error("No certificate data for https $deliveryServiceId domain $domainStr")
        }
        return false
    }

    private fun supportsHttps(deliveryServiceJson: JsonNode?, protocolJson: JsonNode?): Boolean {
        return if ("HTTP" != getDeliveryServiceType(deliveryServiceJson)) {
            false
        } else optBoolean(protocolJson, "acceptHttps")
    }

    companion object {
        private val LOGGER = Logger.getLogger(CertificateChecker::class.java)
    }
}