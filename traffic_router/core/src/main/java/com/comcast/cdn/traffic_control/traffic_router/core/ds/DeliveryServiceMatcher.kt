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
package com.comcast.cdn.traffic_control.traffic_router.core.ds

import com.comcast.cdn.traffic_control.traffic_router.core.request.Request
import com.comcast.cdn.traffic_control.traffic_router.core.request.RequestMatcher
import java.util.TreeMap

class DeliveryServiceMatcher(private var deliveryService: DeliveryService?) : Comparable<DeliveryServiceMatcher?> {
    enum class Type {
        HOST, HEADER, PATH
    }

    private val requestMatchers: MutableList<RequestMatcher?>? = ArrayList()
    fun getDeliveryService(): DeliveryService? {
        return deliveryService
    }

    fun setDeliveryService(deliveryService: DeliveryService?) {
        this.deliveryService = deliveryService
    }

    fun addMatch(type: DeliveryServiceMatcher.Type?, string: String?, target: String?) {
        requestMatchers.add(RequestMatcher(type, string, target))
    }

    fun getRequestMatchers(): MutableList<RequestMatcher?>? {
        return ArrayList(requestMatchers)
    }

    fun matches(request: Request?): Boolean {
        for (matcher in requestMatchers) {
            if (!matcher.matches(request)) {
                return false
            }
        }
        return !requestMatchers.isEmpty()
    }

    override fun equals(deliveryServiceMatcher: Any?): Boolean {
        if (this === deliveryServiceMatcher) return true
        if (deliveryServiceMatcher == null || javaClass != deliveryServiceMatcher.javaClass) return false
        val that = deliveryServiceMatcher as DeliveryServiceMatcher?
        return if (if (deliveryService != null) deliveryService != that.deliveryService else that.deliveryService != null) false else !if (requestMatchers != null) requestMatchers != that.requestMatchers else that.requestMatchers != null
    }

    override fun hashCode(): Int {
        var result = if (deliveryService != null) deliveryService.hashCode() else 0
        result = 31 * result + (requestMatchers?.hashCode() ?: 0)
        return result
    }

    override fun compareTo(that: DeliveryServiceMatcher?): Int {
        if (this === that || this == that) {
            return 0
        }
        val uniqueToThis: MutableSet<RequestMatcher?> = HashSet()
        uniqueToThis.addAll(requestMatchers)
        val uniqueToThat: MutableSet<RequestMatcher?> = HashSet()
        uniqueToThat.addAll(that.requestMatchers)
        for (myRequestMatcher in requestMatchers) {
            if (uniqueToThat.remove(myRequestMatcher)) {
                uniqueToThis.remove(myRequestMatcher)
            }
        }
        val map = TreeMap<RequestMatcher?, DeliveryServiceMatcher?>()
        for (thisMatcher in uniqueToThis) {
            map[thisMatcher] = this
        }
        for (thatMatcher in uniqueToThat) {
            map[thatMatcher] = that
        }
        if (map.isEmpty()) {
            return 0
        }
        return if (this === map.firstEntry().value) -1 else 1
    }

    override fun toString(): String {
        return if (requestMatchers.size > 1) {
            "DeliveryServiceMatcher{" +
                    "deliveryService=" + deliveryService +
                    ", requestMatchers=" + requestMatchers +
                    '}'
        } else "DeliveryServiceMatcher{" +
                "deliveryService=" + deliveryService +
                ", requestMatcher=" + requestMatchers.get(0) +
                '}'
    }
}