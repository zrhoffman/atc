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

import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheRegister
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoResult
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.RouteType
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import org.xbill.DNS.Name
import org.xbill.DNS.Zone

class StatTracker {
    class Tallies {
        fun getCzCount(): Int {
            return czCount
        }

        fun setCzCount(czCount: Int) {
            this.czCount = czCount
        }

        fun getGeoCount(): Int {
            return geoCount
        }

        fun setGeoCount(geoCount: Int) {
            this.geoCount = geoCount
        }

        fun getDeepCzCount(): Int {
            return deepCzCount
        }

        fun setDeepCzCount(deepCzCount: Int) {
            this.deepCzCount = deepCzCount
        }

        fun getDsrCount(): Int {
            return dsrCount
        }

        fun getMissCount(): Int {
            return missCount
        }

        fun setMissCount(missCount: Int) {
            this.missCount = missCount
        }

        fun getErrCount(): Int {
            return errCount
        }

        fun setErrCount(errCount: Int) {
            this.errCount = errCount
        }

        fun getStaticRouteCount(): Int {
            return staticRouteCount
        }

        fun setStaticRouteCount(staticRouteCount: Int) {
            this.staticRouteCount = staticRouteCount
        }

        fun getFedCount(): Int {
            return fedCount
        }

        fun setFedCount(fedCount: Int) {
            this.fedCount = fedCount
        }

        fun getRegionalDeniedCount(): Int {
            return regionalDeniedCount
        }

        fun setRegionalDeniedCount(regionalDeniedCount: Int) {
            this.regionalDeniedCount = regionalDeniedCount
        }

        fun getRegionalAlternateCount(): Int {
            return regionalAlternateCount
        }

        fun setRegionalAlternateCount(regionalAlternateCount: Int) {
            this.regionalAlternateCount = regionalAlternateCount
        }

        var czCount = 0
        var geoCount = 0
        var deepCzCount = 0
        var missCount = 0
        var dsrCount = 0
        var errCount = 0
        var staticRouteCount = 0
        var fedCount = 0
        var regionalDeniedCount = 0
        var regionalAlternateCount = 0
    }

    class Track {
        /**
         * RouteType represents the type of routing performed/to be performed by Traffic Router.
         */
        enum class RouteType {
            /**
             * This value indicates DNS routing is taking/has taken/will take place.
             */
            DNS,

            /**
             * This value indicates HTTP routing is taking/has taken/will take place.
             */
            HTTP
        }

        /**
         * ResultType represents the final result of attempting to route a request.
         */
        enum class ResultType {
            /**
             * This value indicates that an error occurred and routing could not be successfully completed.
             */
            ERROR,

            /**
             * This value indicates that routing was satisfied by a mapping in Coverage Zone configuration.
             */
            CZ,

            /**
             * This value indicates that routing was satisfied by geo-locating the client.
             */
            GEO,

            /**
             * This value indicates that geo-location of the client failed, and they were directed to an appropriate "miss" location.
             */
            MISS,

            /**
             * This value indicates that routing was satisfied by a static DNS entry configured on a Delivery Service.
             */
            STATIC_ROUTE,

            /**
             *
             */
            DS_REDIRECT,

            /**
             * This value indicates that routing could not be performed, because no Delivery Service could be found to match
             * the client request.
             */
            DS_MISS,

            /**
             *
             */
            INIT,

            /**
             * This value indicates that the client was routed according to Federation mappings.
             */
            FED,

            /**
             *
             */
            RGDENY,

            /**
             *
             */
            RGALT,

            /**
             *
             */
            GEO_REDIRECT,

            /**
             * This value indicates that routing was satisfied by a mapping in Deep Coverage Zone configuration.
             */
            DEEP_CZ,

            /**
             * This value indicates that routing was blocked in accordance with anonymous blocking configurations.
             */
            ANON_BLOCK,

            /**
             * This value indicates that routing was based on the default lat/long of the delivery service, because maxmind
             * returned the centre of the country as the client location, due to the CZF not being able to resolve the client IP
             * to a valid location.
             */
            GEO_DS
        }

        enum class ResultDetails {
            NO_DETAILS, DS_NOT_FOUND, DS_TLS_MISMATCH, DS_NO_BYPASS, DS_BYPASS, DS_CZ_ONLY, DS_CLIENT_GEO_UNSUPPORTED, GEO_NO_CACHE_FOUND, REGIONAL_GEO_NO_RULE, REGIONAL_GEO_ALTERNATE_WITHOUT_CACHE, REGIONAL_GEO_ALTERNATE_WITH_CACHE, DS_CZ_BACKUP_CG, DS_INVALID_ROUTING_NAME, LOCALIZED_DNS
        }

        enum class ResultCode {
            NO_RESULT_CODE, NXDOMAIN, NODATA
        }

        var time: Long = 0
        var routeType: RouteType? = null
        var fqdn: String? = null
        var resultCode: ResultCode? = ResultCode.NO_RESULT_CODE
        var result: ResultType? = ResultType.ERROR
        var resultDetails: ResultDetails? = null
        var resultLocation: Geolocation? = null
        var clientGeolocation // the GEO info always retrieved from GEO DB, not from Cache Location
                : Geolocation? = null
        var isClientGeolocationQueried = false
        var regionalGeoResult: RegionalGeoResult? = null
        var fromBackupCzGroup = false

        // in memory switch to track if need to continue geo based
        // defaulting to true, changes the false by router at runtime when primary cache group is configured using fallbackToClosedGeoLoc
        // to false and backup group list is configured and failing
        var continueGeo = true
        override fun toString(): String {
            return "$fqdn - $result"
        }

        fun setRouteType(routeType: RouteType?, fqdn: String?) {
            this.routeType = routeType
            this.fqdn = fqdn
        }

        fun setResultCode(zone: Zone?, qname: Name?, qtype: Int) {
            if (zone == null) {
                return
            }
            val sr = zone.findRecords(qname, qtype)
            if (sr.isNXDOMAIN) {
                resultCode = ResultCode.NXDOMAIN
            } else if (sr.isNXRRSET) {
                resultCode = ResultCode.NODATA
            }
        }

        fun getResultCode(): ResultCode? {
            return resultCode
        }

        fun setResult(result: ResultType?) {
            this.result = result
        }

        fun getResult(): ResultType? {
            return result
        }

        fun setResultDetails(resultDetails: ResultDetails?) {
            this.resultDetails = resultDetails
        }

        fun getResultDetails(): ResultDetails? {
            return resultDetails
        }

        fun setResultLocation(resultLocation: Geolocation?) {
            this.resultLocation = resultLocation
        }

        fun getResultLocation(): Geolocation? {
            return resultLocation
        }

        fun setClientGeolocation(clientGeolocation: Geolocation?) {
            this.clientGeolocation = clientGeolocation
        }

        fun getClientGeolocation(): Geolocation? {
            return clientGeolocation
        }

        fun setClientGeolocationQueried(isClientGeolocationQueried: Boolean) {
            this.isClientGeolocationQueried = isClientGeolocationQueried
        }

        fun isClientGeolocationQueried(): Boolean {
            return isClientGeolocationQueried
        }

        fun setRegionalGeoResult(regionalGeoResult: RegionalGeoResult?) {
            this.regionalGeoResult = regionalGeoResult
        }

        fun getRegionalGeoResult(): RegionalGeoResult? {
            return regionalGeoResult
        }

        fun setFromBackupCzGroup(fromBackupCzGroup: Boolean) {
            this.fromBackupCzGroup = fromBackupCzGroup
        }

        fun isFromBackupCzGroup(): Boolean {
            return fromBackupCzGroup
        }

        fun start() {
            time = System.currentTimeMillis()
        }

        fun end() {
            time = System.currentTimeMillis() - time
        }

        init {
            start()
        }
    }

    private val dnsMap: MutableMap<String?, Tallies?>? = HashMap()
    private val httpMap: MutableMap<String?, Tallies?>? = HashMap()
    fun getDnsMap(): MutableMap<String?, Tallies?>? {
        return dnsMap
    }

    fun getHttpMap(): MutableMap<String?, Tallies?>? {
        return httpMap
    }

    fun getTotalDnsCount(): Long {
        return totalDnsCount
    }

    fun getAverageDnsTime(): Long {
        return if (totalDnsCount == 0L) {
            0
        } else totalDnsTime / totalDnsCount
    }

    fun getTotalHttpCount(): Long {
        return totalHttpCount
    }

    fun getAverageHttpTime(): Long {
        return if (totalHttpCount == 0L) {
            0
        } else totalHttpTime / totalHttpCount
    }

    fun getTotalDsMissCount(): Long {
        return totalDsMissCount
    }

    fun setTotalDsMissCount(totalDsMissCount: Long) {
        this.totalDsMissCount = totalDsMissCount
    }

    private var totalDnsCount: Long = 0
    private var totalDnsTime: Long = 0
    private var totalHttpCount: Long = 0
    private var totalHttpTime: Long = 0
    private var totalDsMissCount: Long = 0
    fun getUpdateTracker(): MutableMap<String?, Long?>? {
        return TrafficRouterManager.Companion.getTimeTracker()
    }

    fun getAppStartTime(): Long {
        return appStartTime
    }

    private var appStartTime: Long = 0
    fun saveTrack(t: Track?) {
        if (t.result == ResultType.DS_MISS) {
            // don't tabulate this, it's for a DS that doesn't exist
            totalDsMissCount++
            return
        }
        t.end()
        synchronized(this) {
            val map: MutableMap<String?, Tallies?>?
            val fqdn = if (t.fqdn == null) "null" else t.fqdn
            if (t.routeType == RouteType.DNS) {
                totalDnsCount++
                totalDnsTime += t.time
                map = dnsMap
                if (t.resultDetails == ResultDetails.LOCALIZED_DNS) {
                    return
                }
            } else {
                totalHttpCount++
                totalHttpTime += t.time
                map = httpMap
            }
            map.putIfAbsent(fqdn, Tallies())
            incTally(t, map.get(fqdn))
        }
    }

    fun init() {
        appStartTime = System.currentTimeMillis()
    }

    fun initialize(initMap: MutableMap<String?, MutableList<String?>?>?, cacheRegister: CacheRegister?) {
        for (dsId in initMap.keys) {
            val dsNames = initMap.get(dsId)
            val ds = cacheRegister.getDeliveryService(dsId)
            if (ds != null) {
                for (i in dsNames.indices) {
                    val t = getTrack()
                    val dsName = StringBuffer(dsNames.get(i))
                    var rt: RouteType
                    if (ds.isDns) {
                        rt = RouteType.DNS
                        if (i == 0) {
                            dsName.insert(0, ds.routingName + ".")
                        } else {
                            continue
                        }
                    } else {
                        rt = RouteType.HTTP
                        dsName.insert(0, ds.routingName + ".")
                    }
                    t.setRouteType(rt, dsName.toString())
                    t.setResult(ResultType.INIT)
                    t.end()
                    saveTrack(t)
                }
            }
        }
    }

    companion object {
        fun getTrack(): Track? {
            return Track()
        }

        private fun incTally(t: Track?, tallies: Tallies?) {
            when (t.result) {
                ResultType.ERROR -> tallies.errCount++
                ResultType.CZ -> tallies.czCount++
                ResultType.GEO -> tallies.geoCount++
                ResultType.DEEP_CZ -> tallies.deepCzCount++
                ResultType.MISS -> tallies.missCount++
                ResultType.DS_REDIRECT -> tallies.dsrCount++
                ResultType.STATIC_ROUTE -> tallies.staticRouteCount++
                ResultType.FED -> tallies.fedCount++
                ResultType.RGDENY -> tallies.regionalDeniedCount++
                ResultType.RGALT -> tallies.regionalAlternateCount++
                else -> {
                }
            }
        }
    }
}