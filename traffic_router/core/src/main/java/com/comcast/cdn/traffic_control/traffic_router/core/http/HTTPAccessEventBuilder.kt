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

import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import java.math.RoundingMode
import java.text.DecimalFormat
import javax.servlet.http.HttpServletRequest

object HTTPAccessEventBuilder {
    private fun formatRequest(request: HttpServletRequest?): String? {
        var url = HTTPAccessEventBuilder.formatObject(request.getRequestURL())
        if ("-" == url) {
            return url
        }
        if (request.getQueryString() != null && !request.getQueryString().isEmpty()) {
            val queryString = "?" + request.getQueryString()
            val stringBuilder = StringBuilder(url)
            stringBuilder.append(queryString)
            url = stringBuilder.toString()
        }
        return url
    }

    private fun formatObject(o: Any?): String? {
        return o?.toString() ?: "-"
    }

    private fun formatRequestHeaders(requestHeaders: MutableMap<String?, String?>?): String? {
        if (requestHeaders == null || requestHeaders.isEmpty()) {
            return "rh=\"-\""
        }
        val stringBuilder = StringBuilder()
        var first = true
        for ((key, value) in requestHeaders) {
            if (value == null || value.isEmpty()) {
                continue
            }
            if (!first) {
                stringBuilder.append(' ')
            } else {
                first = false
            }
            stringBuilder.append("rh=\"")
            stringBuilder.append(key).append(": ")
            stringBuilder.append(value.replace("\"".toRegex(), "'"))
            stringBuilder.append('"')
        }
        return stringBuilder.toString()
    }

    fun create(httpAccessRecord: HTTPAccessRecord?): String? {
        val start = httpAccessRecord.getRequestDate().time
        val timeString = String.format("%d.%03d", start / 1000, start % 1000)
        val httpServletRequest = httpAccessRecord.getRequest()
        var chi = HTTPAccessEventBuilder.formatObject(httpServletRequest.remoteAddr)
        val url = HTTPAccessEventBuilder.formatRequest(httpServletRequest)
        val cqhm = HTTPAccessEventBuilder.formatObject(httpServletRequest.method)
        val cqhv = HTTPAccessEventBuilder.formatObject(httpServletRequest.protocol)
        val resultType = HTTPAccessEventBuilder.formatObject(httpAccessRecord.getResultType())
        val rerr = HTTPAccessEventBuilder.formatObject(httpAccessRecord.getRerr())
        var resultDetails: String? = "-"
        if ("-" != resultType) {
            resultDetails = HTTPAccessEventBuilder.formatObject(httpAccessRecord.getResultDetails())
        }
        var rloc = "-"
        val resultLocation = httpAccessRecord.getResultLocation()
        if (resultLocation != null) {
            val decimalFormat = DecimalFormat("0.00")
            decimalFormat.roundingMode = RoundingMode.DOWN
            rloc = decimalFormat.format(resultLocation.latitude) + "," + decimalFormat.format(resultLocation.longitude)
        }
        val xMmClientIpHeader = httpServletRequest.getHeader(HTTPRequest.Companion.X_MM_CLIENT_IP)
        val fakeIpParameter = httpServletRequest.getParameter(HTTPRequest.Companion.FAKE_IP)
        val remoteIp = chi
        if (xMmClientIpHeader != null) {
            chi = xMmClientIpHeader
        } else if (fakeIpParameter != null) {
            chi = fakeIpParameter
        }
        val rgb = HTTPAccessEventBuilder.formatObject(httpAccessRecord.getRegionalGeoResult())
        val stringBuilder = StringBuilder(timeString)
            .append(" qtype=HTTP chi=")
            .append(chi)
            .append(" rhi=")
        if (remoteIp != chi) {
            stringBuilder.append(remoteIp)
        } else {
            stringBuilder.append('-')
        }
        stringBuilder.append(" url=\"").append(url)
            .append("\" cqhm=").append(cqhm)
            .append(" cqhv=").append(cqhv)
            .append(" rtype=").append(resultType)
            .append(" rloc=\"").append(rloc)
            .append("\" rdtl=").append(resultDetails)
            .append(" rerr=\"").append(rerr)
            .append("\" rgb=\"").append(rgb).append('"')
        if (httpAccessRecord.getResponseCode() != -1) {
            val pssc = HTTPAccessEventBuilder.formatObject(httpAccessRecord.getResponseCode())
            val ttms = (System.nanoTime() - httpAccessRecord.getRequestNanoTime()) / 1000000.0
            stringBuilder.append(" pssc=").append(pssc).append(" ttms=").append(String.format("%.03f", ttms))
        }
        val respurl = " rurl=\"" + HTTPAccessEventBuilder.formatObject(httpAccessRecord.getResponseURL()) + "\""
        stringBuilder.append(respurl)
        val respurls = " rurls=\"" + HTTPAccessEventBuilder.formatObject(httpAccessRecord.getResponseURLs()) + "\""
        stringBuilder.append(respurls)
        val userAgent = httpServletRequest.getHeader("User-Agent") + "\" "
        stringBuilder.append(" uas=\"").append(userAgent)
        stringBuilder.append(HTTPAccessEventBuilder.formatRequestHeaders(httpAccessRecord.getRequestHeaders()))
        return stringBuilder.toString()
    }
}