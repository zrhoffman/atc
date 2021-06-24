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
package com.comcast.cdn.traffic_control.traffic_router.core.secure

import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.util.ProtectedFetcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import java.net.HttpURLConnection
import java.util.Base64

class CertificatesClient {
    private var trafficOpsUtils: TrafficOpsUtils? = null
    private var lastValidfetchTimestamp = 0L
    private var shutdown = false
    private var trafficRouterManager: TrafficRouterManager? = null
    fun refreshData(): MutableList<CertificateData?>? {
        val stringBuilder = StringBuilder()
        trafficRouterManager.trackEvent("lastHttpsCertificatesFetchAttempt")
        var status = fetchRawData(stringBuilder)
        while (status != HttpURLConnection.HTTP_NOT_MODIFIED && status != HttpURLConnection.HTTP_OK) {
            trafficRouterManager.trackEvent("lastHttpsCertificatesFetchFail")
            try {
                Thread.sleep(trafficOpsUtils.getConfigLongValue("certificates.retry.interval", 30 * 1000L))
            } catch (e: InterruptedException) {
                if (!shutdown) {
                    CertificatesClient.Companion.LOGGER.warn(
                        "Interrupted while pausing to fetch certificates from traffic ops",
                        e
                    )
                } else {
                    return null
                }
            }
            trafficRouterManager.trackEvent("lastHttpsCertificatesFetchAttempt")
            status = fetchRawData(stringBuilder)
        }
        if (status == HttpURLConnection.HTTP_NOT_MODIFIED) {
            return null
        }
        lastValidfetchTimestamp = System.currentTimeMillis()
        trafficRouterManager.trackEvent("lastHttpsCertificatesFetchSuccess")
        return getCertificateData(stringBuilder.toString())
    }

    fun fetchRawData(stringBuilder: StringBuilder?): Int {
        while (trafficOpsUtils == null || trafficOpsUtils.getHostname() == null || trafficOpsUtils.getHostname()
                .isEmpty()
        ) {
            CertificatesClient.Companion.LOGGER.error("No traffic ops hostname yet!")
            try {
                Thread.sleep(5000L)
            } catch (e: Exception) {
                CertificatesClient.Companion.LOGGER.info("Interrupted while pausing for check of traffic ops config")
            }
        }
        val certificatesUrl = trafficOpsUtils.getUrl(
            "certificate.api.url",
            "https://\${toHostname}/api/2.0/cdns/name/\${cdnName}/sslkeys"
        )
        try {
            val fetcher =
                ProtectedFetcher(trafficOpsUtils.getAuthUrl(), trafficOpsUtils.getAuthJSON().toString(), 15000)
            return fetcher.getIfModifiedSince(certificatesUrl, 0L, stringBuilder)
        } catch (e: Exception) {
            CertificatesClient.Companion.LOGGER.warn(
                "Failed to fetch data for certificates from " + certificatesUrl + "(" + e.javaClass.simpleName + ") : " + e.message,
                e
            )
        }
        return -1
    }

    fun getCertificateData(jsonData: String?): MutableList<CertificateData?>? {
        try {
            CertificatesClient.Companion.LOGGER.debug("Certificates successfully updated @ $lastValidfetchTimestamp")
            return (ObjectMapper().readValue(
                jsonData,
                object : TypeReference<CertificatesResponse?>() {}) as CertificatesResponse).response
        } catch (e: Exception) {
            CertificatesClient.Companion.LOGGER.warn("Failed parsing json data: " + e.message)
        }
        return ArrayList()
    }

    fun doubleDecode(encoded: String?): Array<String?>? {
        val decodedBytes = Base64.getMimeDecoder().decode(encoded.toByteArray())
        val encodedPemItems: MutableList<String?> = ArrayList()
        val lines: Array<String?> = String(decodedBytes).split("\\r?\\n".toRegex()).toTypedArray()
        val builder = StringBuilder()
        for (line in lines) {
            if (line.startsWith(CertificatesClient.Companion.PEM_FOOTER_PREFIX)) {
                encodedPemItems.add(builder.toString())
                builder.setLength(0)
            }
            builder.append(line)
        }
        if (encodedPemItems.isEmpty()) {
            if (builder.length == 0) {
                CertificatesClient.Companion.LOGGER.warn("Failed base64 decoding")
            } else {
                encodedPemItems.add(builder.toString())
            }
        }
        return encodedPemItems.toTypedArray()
    }

    fun setTrafficOpsUtils(trafficOpsUtils: TrafficOpsUtils?) {
        this.trafficOpsUtils = trafficOpsUtils
    }

    fun setShutdown(shutdown: Boolean) {
        this.shutdown = true
    }

    fun getTrafficRouterManager(): TrafficRouterManager? {
        return trafficRouterManager
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    companion object {
        private val LOGGER = Logger.getLogger(CertificatesClient::class.java)
        private val PEM_FOOTER_PREFIX: String? = "-----END"
    }
}