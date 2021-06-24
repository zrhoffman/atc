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
package com.comcast.cdn.traffic_control.traffic_router.core.dns

import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import org.xbill.DNS.Message
import java.net.InetAddress

// Using Josh Bloch Builder pattern so suppress these warnings.
class DNSAccessRecord private constructor(builder: DNSAccessRecord.Builder?) {
    private val queryInstant: Long
    private val client: InetAddress?
    private val resolver: InetAddress?
    private val dnsMessage: Message?
    private val resultType: ResultType?
    private val resultDetails: ResultDetails?
    private val resultLocation: Geolocation?
    private val requestNanoTime: Long
    fun getQueryInstant(): Long {
        return queryInstant
    }

    fun getClient(): InetAddress? {
        return client
    }

    fun getResolver(): InetAddress? {
        return resolver
    }

    fun getDnsMessage(): Message? {
        return dnsMessage
    }

    fun getResultType(): ResultType? {
        return resultType
    }

    fun getResultDetails(): ResultDetails? {
        return resultDetails
    }

    fun getResultLocation(): Geolocation? {
        return resultLocation
    }

    fun getRequestNanoTime(): Long {
        return requestNanoTime
    }

    class Builder(private val queryInstant: Long, private var client: InetAddress?) {
        private val resolver: InetAddress?
        private var dnsMessage: Message? = null
        private var resultType: ResultType? = null
        private var resultDetails: ResultDetails? = null
        private var resultLocation: Geolocation? = null
        private val requestNanoTime: Long
        fun dnsMessage(query: Message?): DNSAccessRecord.Builder? {
            dnsMessage = query
            return this
        }

        fun client(client: InetAddress?): DNSAccessRecord.Builder? {
            this.client = client
            return this
        }

        fun resultType(resultType: ResultType?): DNSAccessRecord.Builder? {
            this.resultType = resultType
            return this
        }

        fun resultDetails(resultDetails: ResultDetails?): DNSAccessRecord.Builder? {
            this.resultDetails = resultDetails
            return this
        }

        fun resultLocation(resultLocation: Geolocation?): DNSAccessRecord.Builder? {
            this.resultLocation = resultLocation
            return this
        }

        fun build(): DNSAccessRecord? {
            return DNSAccessRecord(this)
        }

        init {
            resolver = client
            requestNanoTime = System.nanoTime()
        }
    }

    init {
        queryInstant = builder.queryInstant
        client = builder.client
        resolver = builder.resolver
        dnsMessage = builder.dnsMessage
        resultType = builder.resultType
        resultDetails = builder.resultDetails
        resultLocation = builder.resultLocation
        requestNanoTime = builder.requestNanoTime
    }
}