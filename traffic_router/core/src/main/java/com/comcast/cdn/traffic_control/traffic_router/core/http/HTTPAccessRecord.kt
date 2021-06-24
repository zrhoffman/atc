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
package com.comcast.cdn.traffic_control.traffic_router.core.http

import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoResult
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import java.net.URL
import java.util.Date
import javax.servlet.http.HttpServletRequest

// Using Josh Bloch Builder pattern so suppress these warnings.
class HTTPAccessRecord private constructor(builder: HTTPAccessRecord.Builder?) {
    private val requestDate: Date?
    private val requestNanoTime: Long
    private val request: HttpServletRequest?
    private val responseURL: URL?
    private val responseURLs: MutableList<URL?>?
    private val responseCode: Int
    private val resultType: ResultType?
    private val rerr: String?
    private val resultDetails: ResultDetails?
    private val resultLocation: Geolocation?
    private val requestHeaders: MutableMap<String?, String?>?
    private val regionalGeoResult: RegionalGeoResult?
    fun getRequestDate(): Date? {
        return requestDate
    }

    fun getRequest(): HttpServletRequest? {
        return request
    }

    fun getResponseCode(): Int {
        return responseCode
    }

    fun getResponseURL(): URL? {
        return responseURL
    }

    fun getResponseURLs(): MutableList<URL?>? {
        return responseURLs
    }

    fun getResultType(): ResultType? {
        return resultType
    }

    fun getRerr(): String? {
        return rerr
    }

    fun getResultDetails(): ResultDetails? {
        return resultDetails
    }

    fun getResultLocation(): Geolocation? {
        return resultLocation
    }

    fun getRequestHeaders(): MutableMap<String?, String?>? {
        return requestHeaders
    }

    fun getRegionalGeoResult(): RegionalGeoResult? {
        return regionalGeoResult
    }

    fun getRequestNanoTime(): Long {
        return requestNanoTime
    }

    class Builder {
        private val requestDate: Date?
        private val request: HttpServletRequest?
        private var responseCode = -1
        private var responseURL: URL? = null
        private var responseURLs: MutableList<URL?>? = null
        private var resultType: ResultType? = null
        private var rerr: String? = null
        private var resultDetails: ResultDetails? = null
        private var resultLocation: Geolocation? = null
        private var requestHeaders: MutableMap<String?, String?>? = HashMap()
        private var regionalGeoResult: RegionalGeoResult? = null
        private val requestNanoTime: Long

        constructor(requestDate: Date?, request: HttpServletRequest?) {
            this.requestDate = requestDate
            this.request = request
            requestNanoTime = System.nanoTime()
        }

        constructor(requestNanoTime: Long, request: HttpServletRequest?) {
            requestDate = Date()
            this.request = request
            this.requestNanoTime = requestNanoTime
        }

        constructor(httpAccessRecord: HTTPAccessRecord?) {
            requestDate = httpAccessRecord.requestDate
            request = httpAccessRecord.request
            responseURL = httpAccessRecord.responseURL
            responseURLs = httpAccessRecord.responseURLs
            responseCode = httpAccessRecord.responseCode
            requestNanoTime = httpAccessRecord.requestNanoTime
        }

        fun responseCode(responseCode: Int): HTTPAccessRecord.Builder? {
            this.responseCode = responseCode
            return this
        }

        fun responseURL(responseURL: URL?): HTTPAccessRecord.Builder? {
            this.responseURL = responseURL
            return this
        }

        fun responseURLs(responseURLs: MutableList<URL?>?): HTTPAccessRecord.Builder? {
            this.responseURLs = responseURLs
            return this
        }

        fun resultType(resultType: ResultType?): HTTPAccessRecord.Builder? {
            this.resultType = resultType
            return this
        }

        fun rerr(rerr: String?): HTTPAccessRecord.Builder? {
            this.rerr = rerr
            return this
        }

        fun resultDetails(resultDetails: ResultDetails?): HTTPAccessRecord.Builder? {
            this.resultDetails = resultDetails
            return this
        }

        fun resultLocation(resultLocation: Geolocation?): HTTPAccessRecord.Builder? {
            this.resultLocation = resultLocation
            return this
        }

        fun requestHeaders(requestHeaders: MutableMap<String?, String?>?): HTTPAccessRecord.Builder? {
            this.requestHeaders = requestHeaders
            return this
        }

        fun regionalGeoResult(regionalGeoResult: RegionalGeoResult?): HTTPAccessRecord.Builder? {
            this.regionalGeoResult = regionalGeoResult
            return this
        }

        fun build(): HTTPAccessRecord? {
            return HTTPAccessRecord(this)
        }
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as HTTPAccessRecord?
        if (requestNanoTime != that.requestNanoTime) return false
        if (responseCode != that.responseCode) return false
        if (if (requestDate != null) requestDate != that.requestDate else that.requestDate != null) return false
        if (if (request != null) request != that.request else that.request != null) return false
        if (if (responseURL != null) responseURL != that.responseURL else that.responseURL != null) return false
        if (if (responseURLs != null) responseURLs != that.responseURLs else that.responseURLs != null) return false
        if (resultType != that.resultType) return false
        if (if (rerr != null) rerr != that.rerr else that.rerr != null) return false
        if (resultDetails != that.resultDetails) return false
        if (if (resultLocation != null) resultLocation != that.resultLocation else that.resultLocation != null) return false
        if (if (requestHeaders != null) requestHeaders != that.requestHeaders else that.requestHeaders != null) return false
        return if (regionalGeoResult != null) regionalGeoResult == that.regionalGeoResult else that.regionalGeoResult == null
    }

    override fun hashCode(): Int {
        var result = requestDate?.hashCode() ?: 0
        result = 31 * result + (requestNanoTime xor (requestNanoTime ushr 32)) as Int
        result = 31 * result + (request?.hashCode() ?: 0)
        result = 31 * result + (responseURL?.hashCode() ?: 0)
        result = 31 * result + (responseURLs?.hashCode() ?: 0)
        result = 31 * result + responseCode
        result = 31 * result + (resultType?.hashCode() ?: 0)
        result = 31 * result + (rerr?.hashCode() ?: 0)
        result = 31 * result + (resultDetails?.hashCode() ?: 0)
        result = 31 * result + (resultLocation?.hashCode() ?: 0)
        result = 31 * result + (requestHeaders?.hashCode() ?: 0)
        result = 31 * result + (regionalGeoResult?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "HTTPAccessRecord{" +
                "requestDate=" + requestDate +
                ", request=" + request +
                ", responseURL=" + responseURL +
                ", responseURLs=" + responseURLs +
                ", responseCode=" + responseCode +
                ", resultType=" + resultType +
                ", rerr='" + rerr + '\'' +
                ", resultDetails=" + resultDetails +
                ", rgb=" + regionalGeoResult +
                ", requestNanoTime=" + requestNanoTime +
                '}'
    }

    init {
        requestDate = builder.requestDate
        request = builder.request
        responseCode = builder.responseCode
        responseURL = builder.responseURL
        responseURLs = builder.responseURLs
        resultType = builder.resultType
        rerr = builder.rerr
        resultDetails = builder.resultDetails
        resultLocation = builder.resultLocation
        requestHeaders = builder.requestHeaders
        regionalGeoResult = builder.regionalGeoResult
        requestNanoTime = builder.requestNanoTime
    }
}