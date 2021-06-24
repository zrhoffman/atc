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
import com.comcast.cdn.traffic_control.traffic_router.core.router.HTTPRouteResult
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
import org.apache.log4j.Logger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.lang.Boolean
import java.util.Date
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.String
import kotlin.Throws
import kotlin.toString

class RouterFilter : OncePerRequestFilter() {
    @Autowired
    private val trafficRouterManager: TrafficRouterManager? = null

    @Autowired
    private val statTracker: StatTracker? = null
    private var staticContentWhiteList: MutableList<String?>? = null
    private var doNotLog = false

    @Throws(IOException::class, ServletException::class)
    public override fun doFilterInternal(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        chain: FilterChain?
    ) {
        val requestDate = Date()
        if (request.getLocalPort() == trafficRouterManager.getApiPort() || request.getLocalPort() == trafficRouterManager.getSecureApiPort()) {
            chain.doFilter(request, response)
            return
        }
        if (staticContentWhiteList.contains(request.getRequestURI())) {
            chain.doFilter(request, response)
            if (doNotLog) {
                return
            }
            val access = HTTPAccessRecord.Builder(requestDate, request).build()
            RouterFilter.Companion.ACCESS.info(HTTPAccessEventBuilder.create(access))
            return
        }
        val httpAccessRecord = HTTPAccessRecord.Builder(requestDate, request).build()
        writeHttpResponse(response, request, HTTPRequest(request), StatTracker.Companion.getTrack(), httpAccessRecord)
    }

    @Throws(IOException::class)
    private fun writeHttpResponse(
        response: HttpServletResponse?, httpServletRequest: HttpServletRequest?,
        request: HTTPRequest?, track: StatTracker.Track?, httpAccessRecord: HTTPAccessRecord?
    ) {
        val httpAccessRecordBuilder = HTTPAccessRecord.Builder(httpAccessRecord)
        var routeResult: HTTPRouteResult? = null
        try {
            val trafficRouter = trafficRouterManager.getTrafficRouter()
            routeResult = trafficRouter.route(request, track)
            if (routeResult == null || routeResult.url == null) {
                setErrorResponseCode(response, httpAccessRecordBuilder, routeResult)
            } else if (routeResult.isMultiRouteRequest) {
                setMultiResponse(routeResult, httpServletRequest, response, httpAccessRecordBuilder)
            } else {
                setSingleResponse(routeResult, httpServletRequest, response, httpAccessRecordBuilder)
            }
        } catch (e: IOException) {
            httpAccessRecordBuilder.responseCode(-1)
            httpAccessRecordBuilder.responseURL(null)
            httpAccessRecordBuilder.rerr(e.message)
            throw e
        } catch (e: GeolocationException) {
            httpAccessRecordBuilder.responseCode(-1)
            httpAccessRecordBuilder.responseURL(null)
            httpAccessRecordBuilder.rerr(e.message)
        } finally {
            val requestHeaders = trafficRouterManager.getTrafficRouter().requestHeaders
            if (routeResult != null && routeResult.requestHeaders != null) {
                requestHeaders.addAll(routeResult.requestHeaders)
            }
            val accessRequestHeaders = HttpAccessRequestHeaders().makeMap(httpServletRequest, requestHeaders)
            val access = httpAccessRecordBuilder.resultType(track.getResult())
                .resultDetails(track.getResultDetails())
                .resultLocation(track.getResultLocation())
                .requestHeaders(accessRequestHeaders)
                .regionalGeoResult(track.getRegionalGeoResult())
                .build()
            RouterFilter.Companion.ACCESS.info(HTTPAccessEventBuilder.create(access))
            statTracker.saveTrack(track)
        }
    }

    @Throws(IOException::class)
    private fun setMultiResponse(
        routeResult: HTTPRouteResult?,
        httpServletRequest: HttpServletRequest?,
        response: HttpServletResponse?,
        httpAccessRecordBuilder: HTTPAccessRecord.Builder?
    ) {
        if (routeResult.getDeliveryService() != null) {
            val responseHeaders = routeResult.getDeliveryService().responseHeaders
            for (key in responseHeaders.keys) {
                // if two DSs append the same header, the last one wins; no way around it unless we enforce unique response headers between subordinate DSs
                response.addHeader(key, responseHeaders[key])
            }
        }
        val redirect = httpServletRequest.getParameter(RouterFilter.Companion.REDIRECT_QUERY_PARAM)
        if (RouterFilter.Companion.HEAD != httpServletRequest.getMethod()) {
            response.setContentType("application/json")
            response.getWriter().println(routeResult.toMultiLocationJSONString())
            httpAccessRecordBuilder.responseURLs(routeResult.getUrls())
        }

        // don't actually parse the boolean value; trred would always be false unless the query param is "true"
        if ("false".equals(redirect, ignoreCase = true)) {
            response.setStatus(HttpServletResponse.SC_OK)
            httpAccessRecordBuilder.responseCode(HttpServletResponse.SC_OK)
        } else {
            response.setHeader("Location", routeResult.getUrl().toString())
            response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY)
            httpAccessRecordBuilder.responseCode(HttpServletResponse.SC_MOVED_TEMPORARILY)
            httpAccessRecordBuilder.responseURL(routeResult.getUrl())
        }
    }

    @Throws(IOException::class)
    private fun setSingleResponse(
        routeResult: HTTPRouteResult?,
        httpServletRequest: HttpServletRequest?,
        response: HttpServletResponse?,
        httpAccessRecordBuilder: HTTPAccessRecord.Builder?
    ) {
        val redirect = httpServletRequest.getParameter(RouterFilter.Companion.REDIRECT_QUERY_PARAM)
        val format = httpServletRequest.getParameter("format")
        val location = routeResult.getUrl()
        if (routeResult.getDeliveryService() != null) {
            val deliveryService = routeResult.getDeliveryService()
            val responseHeaders = deliveryService.responseHeaders
            for (key in responseHeaders.keys) {
                response.addHeader(key, responseHeaders[key])
            }
        }
        if ("false".equals(redirect, ignoreCase = true)) {
            if (RouterFilter.Companion.HEAD != httpServletRequest.getMethod()) {
                response.setContentType("application/json")
                response.getWriter().println(routeResult.toMultiLocationJSONString())
                httpAccessRecordBuilder.responseURLs(routeResult.getUrls())
            }
            httpAccessRecordBuilder.responseCode(HttpServletResponse.SC_OK)
        } else if ("json" == format) {
            if (RouterFilter.Companion.HEAD != httpServletRequest.getMethod()) {
                response.setContentType("application/json")
                response.getWriter().println(routeResult.toLocationJSONString())
                httpAccessRecordBuilder.responseURL(location)
            }
            httpAccessRecordBuilder.responseCode(HttpServletResponse.SC_OK)
        } else {
            response.sendRedirect(location.toString())
            httpAccessRecordBuilder.responseCode(HttpServletResponse.SC_MOVED_TEMPORARILY)
            httpAccessRecordBuilder.responseURL(location)
        }
    }

    @Throws(IOException::class)
    private fun setErrorResponseCode(
        response: HttpServletResponse?,
        httpAccessRecordBuilder: HTTPAccessRecord.Builder?, result: HTTPRouteResult?
    ) {
        if (result != null && result.responseCode > 0) {
            httpAccessRecordBuilder.responseCode(result.responseCode)
            response.sendError(result.responseCode)
            return
        }
        httpAccessRecordBuilder.responseCode(HttpServletResponse.SC_SERVICE_UNAVAILABLE)
        response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE)
    }

    fun setDoNotLog(logAccessString: String?) {
        doNotLog = Boolean.valueOf(logAccessString)
    }

    fun setStaticContentWhiteList(staticContentWhiteList: MutableList<String?>?) {
        this.staticContentWhiteList = staticContentWhiteList
    }

    companion object {
        private val ACCESS = Logger.getLogger("com.comcast.cdn.traffic_control.traffic_router.core.access")
        val REDIRECT_QUERY_PARAM: String? = "trred"
        private val HEAD: String? = "HEAD"
    }
}