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
import com.comcast.cdn.traffic_control.traffic_router.core.ds.Dispersion
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation.LocalizationMethod
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheRegister
import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Node.IPVersions
import com.comcast.cdn.traffic_control.traffic_router.core.hash.ConsistentHasher
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.request.DNSRequest
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.request.Request
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.util.CidrAddress
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import org.hamcrest.MatcherAssert
import org.junit.Before
import org.junit.Test
import org.mockito.Matchers
import org.mockito.Mockito
import org.powermock.reflect.Whitebox
import org.xbill.DNS.Name
import org.xbill.DNS.Type

class TrafficRouterTest {
    private var consistentHasher: ConsistentHasher? = null
    private var trafficRouter: TrafficRouter = Mockito.mock(TrafficRouter::class.java)
    private var deliveryService: DeliveryService = Mockito.mock(DeliveryService::class.java)
    private var federationRegistry: FederationRegistry = Mockito.mock(FederationRegistry::class.java)

    @Before
    @Throws(Exception::class)
    fun before() {
        deliveryService = Mockito.mock(DeliveryService::class.java)
        Mockito.`when`(deliveryService.isAvailable()).thenReturn(true)
        Mockito.`when`(deliveryService.isCoverageZoneOnly()).thenReturn(false)
        Mockito.`when`(deliveryService.getDispersion()).thenReturn(
            Mockito.mock(
                Dispersion::class.java
            )
        )
        Mockito.`when`(deliveryService.isAcceptHttp()).thenReturn(true)
        consistentHasher = Mockito.mock(ConsistentHasher::class.java)
        Mockito.`when`(
            deliveryService.createURIString(
                Matchers.any(
                    HTTPRequest::class.java
                ), Matchers.any(
                    Cache::class.java
                )
            )
        ).thenReturn("http://atscache.kabletown.net/index.html")
        val inetRecords: MutableList<InetRecord> = ArrayList()
        val inetRecord = InetRecord("cname1", 12345)
        inetRecords.add(inetRecord)
        federationRegistry = Mockito.mock(FederationRegistry::class.java)
        Mockito.`when`(
            federationRegistry.findInetRecords(
                Matchers.anyString(), Matchers.any(
                    CidrAddress::class.java
                )
            )
        ).thenReturn(inetRecords)
        trafficRouter = Mockito.mock(TrafficRouter::class.java)
        val cacheRegister = Mockito.mock(CacheRegister::class.java)
        Mockito.`when`(
            cacheRegister.getDeliveryService(
                Matchers.any(
                    HTTPRequest::class.java
                )
            )
        ).thenReturn(deliveryService)
        Whitebox.setInternalState(trafficRouter, "cacheRegister", cacheRegister)
        Whitebox.setInternalState(trafficRouter, "federationRegistry", federationRegistry)
        Whitebox.setInternalState(trafficRouter, "consistentHasher", consistentHasher)
        Whitebox.setInternalState(
            trafficRouter, "steeringRegistry", Mockito.mock(
                SteeringRegistry::class.java
            )
        )
        Mockito.`when`(
            trafficRouter.route(
                Matchers.any(DNSRequest::class.java), Matchers.any(
                    StatTracker.Track::class.java
                )
            )
        ).thenCallRealMethod()
        Mockito.`when`(
            trafficRouter.route(
                Matchers.any(
                    HTTPRequest::class.java
                ), Matchers.any(StatTracker.Track::class.java)
            )
        ).thenCallRealMethod()
        Mockito.`when`(
            trafficRouter.singleRoute(
                Matchers.any(
                    HTTPRequest::class.java
                ), Matchers.any(StatTracker.Track::class.java)
            )
        ).thenCallRealMethod()
        Mockito.`when`(
            trafficRouter.selectDeliveryService(
                Matchers.any(
                    Request::class.java
                )
            )
        ).thenReturn(deliveryService)
        Mockito.`when`(
            trafficRouter.consistentHashDeliveryService(
                Matchers.any(
                    DeliveryService::class.java
                ), Matchers.any(HTTPRequest::class.java), Matchers.anyString()
            )
        ).thenCallRealMethod()
    }

    @Test
    @Throws(Exception::class)
    fun itCreatesDnsResultsFromFederationMappingHit() {
        val name = Name.fromString("edge.example.com")
        val request = DNSRequest("example.com", name, Type.A)
        request.clientIP = "192.168.10.11"
        request.hostname = name.relativize(Name.root).toString()
        val track = Mockito.spy(StatTracker.getTrack())
        Mockito.`when`(deliveryService.routingName).thenReturn("edge")
        Mockito.`when`(deliveryService.isDns).thenReturn(true)
        val result = trafficRouter.route(request, track)
        MatcherAssert.assertThat(
            result.addresses,
            org.hamcrest.Matchers.containsInAnyOrder(InetRecord("cname1", 12345))
        )
        Mockito.verify(track).setRouteType(StatTracker.Track.RouteType.DNS, "edge.example.com")
    }

    @Test
    @Throws(Exception::class)
    fun itCreatesHttpResults() {
        val httpRequest = HTTPRequest()
        httpRequest.clientIP = "192.168.10.11"
        httpRequest.hostname = "ccr.example.com"
        val track = Mockito.spy(StatTracker.getTrack())
        val cache = Mockito.mock(
            Cache::class.java
        )
        Mockito.`when`(cache.hasDeliveryService(Matchers.anyString())).thenReturn(true)
        val cacheLocation = CacheLocation("", Geolocation(50.0, 50.0))
        cacheLocation.addCache(cache)
        val cacheLocationCollection: MutableSet<CacheLocation> = HashSet()
        cacheLocationCollection.add(cacheLocation)
        val cacheRegister = Mockito.mock(CacheRegister::class.java)
        Mockito.`when`(cacheRegister.cacheLocations).thenReturn(cacheLocationCollection)
        Mockito.`when`<List<*>>(
            deliveryService.filterAvailableLocations(
                Matchers.any<Collection<CacheLocation>>()
            )
        ).thenCallRealMethod()
        Mockito.`when`(deliveryService.isLocationAvailable(cacheLocation)).thenReturn(true)
        val caches: MutableList<Cache> = ArrayList()
        caches.add(cache)
        Mockito.`when`(
            trafficRouter.selectCaches(
                Matchers.any(
                    HTTPRequest::class.java
                ), Matchers.any(DeliveryService::class.java), Matchers.any(
                    StatTracker.Track::class.java
                )
            )
        ).thenReturn(caches)
        Mockito.`when`(
            trafficRouter.selectCachesByGeo(
                Matchers.anyString(), Matchers.any(
                    DeliveryService::class.java
                ), Matchers.any(CacheLocation::class.java), Matchers.any(
                    StatTracker.Track::class.java
                ), Matchers.any(IPVersions::class.java)
            )
        ).thenCallRealMethod()
        Mockito.`when`(
            trafficRouter.getClientLocation(
                Matchers.anyString(), Matchers.any(
                    DeliveryService::class.java
                ), Matchers.any(CacheLocation::class.java), Matchers.any(
                    StatTracker.Track::class.java
                )
            )
        ).thenReturn(Geolocation(40.0, -100.0))
        Mockito.`when`(
            trafficRouter.getCachesByGeo(
                Matchers.any(
                    DeliveryService::class.java
                ), Matchers.any(Geolocation::class.java), Matchers.any(
                    StatTracker.Track::class.java
                ), Matchers.any(IPVersions::class.java)
            )
        ).thenCallRealMethod()
        Mockito.`when`(trafficRouter.cacheRegister).thenReturn(cacheRegister)
        Mockito.`when`<List<*>>(
            trafficRouter.orderLocations(
                Matchers.any<List<CacheLocation>>(), Matchers.any(Geolocation::class.java)
            )
        ).thenCallRealMethod()
        val httpRouteResult = trafficRouter.route(httpRequest, track)
        MatcherAssert.assertThat(
            httpRouteResult.url.toString(),
            org.hamcrest.Matchers.equalTo("http://atscache.kabletown.net/index.html")
        )
    }

    @Test
    @Throws(Exception::class)
    fun itFiltersByIPAvailability() {
        val ds = Mockito.mock(DeliveryService::class.java)
        val cacheIPv4 = Mockito.mock(
            Cache::class.java
        )
        Mockito.`when`(cacheIPv4.hasDeliveryService(Matchers.anyString())).thenReturn(true)
        Mockito.`when`(cacheIPv4.hasAuthority()).thenReturn(true)
        Mockito.`when`(cacheIPv4.isAvailable(Matchers.any(IPVersions::class.java))).thenCallRealMethod()
        Mockito.doCallRealMethod().`when`(cacheIPv4).setIsAvailable(Matchers.anyBoolean())
        Whitebox.setInternalState(cacheIPv4, "ipv4Available", true)
        Whitebox.setInternalState(cacheIPv4, "ipv6Available", false)
        cacheIPv4.setIsAvailable(true)
        Mockito.`when`(cacheIPv4.id).thenReturn("cache IPv4")
        val cacheIPv6 = Mockito.mock(
            Cache::class.java
        )
        Mockito.`when`(cacheIPv6.hasDeliveryService(Matchers.anyString())).thenReturn(true)
        Mockito.`when`(cacheIPv6.hasAuthority()).thenReturn(true)
        Mockito.`when`(cacheIPv6.isAvailable(Matchers.any(IPVersions::class.java))).thenCallRealMethod()
        Mockito.doCallRealMethod().`when`(cacheIPv6).setIsAvailable(Matchers.anyBoolean())
        Whitebox.setInternalState(cacheIPv6, "ipv4Available", false)
        Whitebox.setInternalState(cacheIPv6, "ipv6Available", true)
        cacheIPv6.setIsAvailable(true)
        Mockito.`when`(cacheIPv6.id).thenReturn("cache IPv6")
        val caches: MutableList<Cache> = ArrayList()
        caches.add(cacheIPv4)
        caches.add(cacheIPv6)
        Mockito.`when`<List<*>>(
            trafficRouter.getSupportingCaches(
                Matchers.any<List<Cache>>(), Matchers.any(DeliveryService::class.java), Matchers.any(
                    IPVersions::class.java
                )
            )
        ).thenCallRealMethod()
        val supportingIPv4Caches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.IPV4ONLY)
        MatcherAssert.assertThat(supportingIPv4Caches.size, org.hamcrest.Matchers.equalTo(1))
        MatcherAssert.assertThat(supportingIPv4Caches[0].id, org.hamcrest.Matchers.equalTo("cache IPv4"))
        val supportingIPv6Caches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.IPV6ONLY)
        MatcherAssert.assertThat(supportingIPv6Caches.size, org.hamcrest.Matchers.equalTo(1))
        MatcherAssert.assertThat(supportingIPv6Caches[0].id, org.hamcrest.Matchers.equalTo("cache IPv6"))
        val supportingEitherCaches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.ANY)
        MatcherAssert.assertThat(supportingEitherCaches.size, org.hamcrest.Matchers.equalTo(2))
        cacheIPv6.setIsAvailable(false)
        val supportingAvailableCaches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.ANY)
        MatcherAssert.assertThat(supportingAvailableCaches.size, org.hamcrest.Matchers.equalTo(1))
        MatcherAssert.assertThat(supportingAvailableCaches[0].id, org.hamcrest.Matchers.equalTo("cache IPv4"))
    }

    @Test
    @Throws(Exception::class)
    fun itChecksDefaultLocation() {
        val ip = "1.2.3.4"
        val track = StatTracker.Track()
        val geolocation = Mockito.mock(Geolocation::class.java)
        Mockito.`when`(trafficRouter.getClientLocation(ip, deliveryService, null, track)).thenReturn(geolocation)
        Mockito.`when`(geolocation.isDefaultLocation).thenReturn(true)
        Mockito.`when`(geolocation.countryCode).thenReturn("US")
        val map: MutableMap<String, Geolocation> = HashMap()
        val defaultUSLocation = Geolocation(37.751, -97.822)
        defaultUSLocation.countryCode = "US"
        map["US"] = defaultUSLocation
        Mockito.`when`(trafficRouter.defaultGeoLocationsOverride).thenReturn(map)
        val cache = Mockito.mock(
            Cache::class.java
        )
        val list: MutableList<Cache> = ArrayList()
        list.add(cache)
        Mockito.`when`(deliveryService.missLocation).thenReturn(defaultUSLocation)
        Mockito.`when`(
            trafficRouter.getCachesByGeo(deliveryService, deliveryService.missLocation, track, IPVersions.IPV4ONLY)
        ).thenReturn(list)
        Mockito.`when`(
            trafficRouter.selectCachesByGeo(ip, deliveryService, null, track, IPVersions.IPV4ONLY)
        ).thenCallRealMethod()
        Mockito.`when`(trafficRouter.isValidMissLocation(deliveryService)).thenCallRealMethod()
        val result = trafficRouter.selectCachesByGeo(ip, deliveryService, null, track, IPVersions.IPV4ONLY)
        Mockito.verify(trafficRouter)
            .getCachesByGeo(deliveryService, deliveryService.missLocation, track, IPVersions.IPV4ONLY)
        MatcherAssert.assertThat(result.size, org.hamcrest.Matchers.equalTo(1))
        MatcherAssert.assertThat(result[0], org.hamcrest.Matchers.equalTo(cache))
        MatcherAssert.assertThat(track.getResult(), org.hamcrest.Matchers.equalTo(ResultType.GEO_DS))
    }

    @Test
    @Throws(Exception::class)
    fun itChecksMissLocation() {
        var defaultUSLocation = Geolocation(37.751, -97.822)
        Mockito.`when`(deliveryService.missLocation).thenReturn(defaultUSLocation)
        Mockito.`when`(trafficRouter.isValidMissLocation(deliveryService)).thenCallRealMethod()
        var result = trafficRouter.isValidMissLocation(deliveryService)
        MatcherAssert.assertThat(result, org.hamcrest.Matchers.equalTo(true))
        defaultUSLocation = Geolocation(0.0, 0.0)
        Mockito.`when`(deliveryService.missLocation).thenReturn(defaultUSLocation)
        result = trafficRouter.isValidMissLocation(deliveryService)
        MatcherAssert.assertThat(result, org.hamcrest.Matchers.equalTo(false))
    }

    @Test
    @Throws(Exception::class)
    fun itSetsResultToGeo() {
        val cache = Mockito.mock(
            Cache::class.java
        )
        Mockito.`when`(cache.hasDeliveryService(Matchers.anyString())).thenReturn(true)
        val cacheLocation = CacheLocation("", Geolocation(50.0, 50.0))
        cacheLocation.addCache(cache)
        val cacheLocationCollection: MutableSet<CacheLocation> = HashSet()
        cacheLocationCollection.add(cacheLocation)
        val cacheRegister = Mockito.mock(CacheRegister::class.java)
        Mockito.`when`(cacheRegister.cacheLocations).thenReturn(cacheLocationCollection)
        Mockito.`when`(trafficRouter.cacheRegister).thenReturn(cacheRegister)
        Mockito.`when`(deliveryService.isLocationAvailable(cacheLocation)).thenReturn(true)
        Mockito.`when`<List<*>>(
            deliveryService.filterAvailableLocations(
                Matchers.any<Collection<CacheLocation>>()
            )
        ).thenCallRealMethod()
        Mockito.`when`(
            trafficRouter.selectCaches(
                Matchers.any(
                    HTTPRequest::class.java
                ), Matchers.any(DeliveryService::class.java), Matchers.any(
                    StatTracker.Track::class.java
                )
            )
        ).thenCallRealMethod()
        Mockito.`when`(
            trafficRouter.selectCaches(
                Matchers.any(
                    HTTPRequest::class.java
                ), Matchers.any(DeliveryService::class.java), Matchers.any(
                    StatTracker.Track::class.java
                ), Matchers.anyBoolean()
            )
        ).thenCallRealMethod()
        Mockito.`when`(
            trafficRouter.selectCachesByGeo(
                Matchers.anyString(), Matchers.any(
                    DeliveryService::class.java
                ), Matchers.any(CacheLocation::class.java), Matchers.any(
                    StatTracker.Track::class.java
                ), Matchers.any(IPVersions::class.java)
            )
        ).thenCallRealMethod()
        val clientLocation = Geolocation(40.0, -100.0)
        Mockito.`when`(
            trafficRouter.getClientLocation(
                Matchers.anyString(), Matchers.any(
                    DeliveryService::class.java
                ), Matchers.any(CacheLocation::class.java), Matchers.any(
                    StatTracker.Track::class.java
                )
            )
        ).thenReturn(clientLocation)
        Mockito.`when`(
            trafficRouter.getCachesByGeo(
                Matchers.any(
                    DeliveryService::class.java
                ), Matchers.any(Geolocation::class.java), Matchers.any(
                    StatTracker.Track::class.java
                ), Matchers.any(IPVersions::class.java)
            )
        ).thenCallRealMethod()
        Mockito.`when`<List<*>>(
            trafficRouter.filterEnabledLocations(
                Matchers.any<List<CacheLocation>>(), Matchers.any(LocalizationMethod::class.java)
            )
        ).thenCallRealMethod()
        Mockito.`when`<List<*>>(
            trafficRouter.orderLocations(
                Matchers.any<List<CacheLocation>>(), Matchers.any(Geolocation::class.java)
            )
        ).thenCallRealMethod()
        Mockito.`when`<List<*>>(
            trafficRouter.getSupportingCaches(
                Matchers.any<List<Cache>>(), Matchers.any(DeliveryService::class.java), Matchers.any(
                    IPVersions::class.java
                )
            )
        ).thenCallRealMethod()
        val httpRequest = HTTPRequest()
        httpRequest.clientIP = "192.168.10.11"
        httpRequest.hostname = "ccr.example.com"
        httpRequest.path = "/some/path"
        var track = Mockito.spy(StatTracker.getTrack())
        trafficRouter.route(httpRequest, track)
        MatcherAssert.assertThat(track.getResult(), org.hamcrest.Matchers.equalTo(ResultType.GEO))
        MatcherAssert.assertThat(track.getResultLocation(), org.hamcrest.Matchers.equalTo(Geolocation(50.0, 50.0)))
        Mockito.`when`(
            federationRegistry.findInetRecords(
                Matchers.anyString(), Matchers.any(
                    CidrAddress::class.java
                )
            )
        ).thenReturn(null)
        Mockito.`when`(deliveryService.routingName).thenReturn("edge")
        Mockito.`when`(deliveryService.isDns).thenReturn(true)
        val name = Name.fromString("edge.example.com")
        val dnsRequest = DNSRequest("example.com", name, Type.A)
        dnsRequest.clientIP = "10.10.10.10"
        dnsRequest.hostname = name.relativize(Name.root).toString()
        track = StatTracker.getTrack()
        trafficRouter.route(dnsRequest, track)
        MatcherAssert.assertThat(track.getResult(), org.hamcrest.Matchers.equalTo(ResultType.GEO))
        MatcherAssert.assertThat(track.getResultLocation(), org.hamcrest.Matchers.equalTo(Geolocation(50.0, 50.0)))
    }

    @Test
    @Throws(Exception::class)
    fun itRetainsPathElementsInURI() {
        val cache = Mockito.mock(
            Cache::class.java
        )
        Mockito.`when`(cache.fqdn).thenReturn("atscache-01.kabletown.net")
        Mockito.`when`(cache.port).thenReturn(80)
        Mockito.`when`(
            deliveryService.createURIString(
                Matchers.any(
                    HTTPRequest::class.java
                ), Matchers.any(
                    Cache::class.java
                )
            )
        ).thenCallRealMethod()
        val httpRequest = HTTPRequest()
        httpRequest.clientIP = "192.168.10.11"
        httpRequest.hostname = "tr.ds.kabletown.net"
        httpRequest.path = "/782-93d215fcd88b/6b6ce2889-ae4c20a1584.ism/manifest(format=m3u8-aapl).m3u8"
        httpRequest.uri =
            "/782-93d215fcd88b/6b6ce2889-ae4c20a1584.ism;urlsig=O0U9MTQ1Ojhx74tjchm8yzfdanshdafHMNhv8vNA/manifest(format=m3u8-aapl).m3u8"
        val dest = StringBuilder()
        dest.append("http://")
        dest.append(cache.fqdn.split("\\.".toRegex(), 2).toTypedArray()[0])
        dest.append(".")
        dest.append(httpRequest.hostname.split("\\.".toRegex(), 2).toTypedArray()[1])
        dest.append(httpRequest.uri)
        MatcherAssert.assertThat(
            deliveryService.createURIString(httpRequest, cache),
            org.hamcrest.Matchers.equalTo(dest.toString())
        )
    }
}