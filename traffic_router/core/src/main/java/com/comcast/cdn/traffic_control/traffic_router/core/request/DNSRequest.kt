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
package com.comcast.cdn.traffic_control.traffic_router.core.request

import org.xbill.DNS.Name
import org.xbill.DNS.Zone

class DNSRequest : Request {
    private val name: Name?
    private val zoneName: String?
    private val queryType: Int
    private var dnssec = false

    constructor(zoneName: String?, name: Name?, queryType: Int) : super() {
        this.queryType = queryType
        this.name = name
        this.zoneName = zoneName
    }

    constructor(zone: Zone?, name: Name?, queryType: Int) : super() {
        this.queryType = queryType
        this.name = name
        zoneName = zone.getOrigin().toString().toLowerCase()
    }

    fun getQueryType(): Int {
        return queryType
    }

    override fun getType(): String? {
        return "dns"
    }

    fun isDnssec(): Boolean {
        return dnssec
    }

    fun setDnssec(dnssec: Boolean) {
        this.dnssec = dnssec
    }

    fun getName(): Name? {
        return name
    }

    fun getZoneName(): String? {
        return zoneName
    }
}