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
package com.comcast.cdn.traffic_control.traffic_router.core.router

import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import java.net.URL
import java.util.*

class HTTPRouteResult(private val multiRouteRequest: Boolean) : RouteResult {
    private val urls: MutableList<URL?>? = ArrayList()
    private val deliveryServices: MutableList<DeliveryService?>? = ArrayList()
    private var responseCode = 0
    override fun getResult(): Any? {
        return getUrls()
    }

    fun getUrls(): MutableList<URL?>? {
        return urls
    }

    fun addUrl(url: URL?) {
        urls.add(url)
    }

    fun getUrl(): URL? {
        return if (!urls.isEmpty()) urls.get(0) else null
    }

    fun setUrl(url: URL?) {
        urls.clear()
        urls.add(url)
    }

    fun getDeliveryServices(): MutableList<DeliveryService?>? {
        return deliveryServices
    }

    fun addDeliveryService(deliveryService: DeliveryService?) {
        deliveryServices.add(deliveryService)
    }

    fun getDeliveryService(): DeliveryService? {
        return if (!deliveryServices.isEmpty()) deliveryServices.get(0) else null
    }

    fun setDeliveryService(deliveryService: DeliveryService?) {
        deliveryServices.clear()
        deliveryServices.add(deliveryService)
    }

    fun getResponseCode(): Int {
        return responseCode
    }

    fun setResponseCode(rc: Int) {
        responseCode = rc
    }

    fun toLocationJSONString(): String? {
        return "{\"location\": \"" + getUrl().toString() + "\" }"
    }

    fun toMultiLocationJSONString(): String? {
        val joiner = StringJoiner("\",\"")
        for (url in urls) {
            joiner.add(url.toString())
        }
        return "{\"locations\":[\"$joiner\"]}"
    }

    fun getRequestHeaders(): MutableSet<String?>? {
        val requestHeaders: MutableSet<String?> = HashSet()
        for (deliveryService in getDeliveryServices()) {
            requestHeaders.addAll(deliveryService.getRequestHeaders())
        }
        return requestHeaders
    }

    fun isMultiRouteRequest(): Boolean {
        return multiRouteRequest
    }
}