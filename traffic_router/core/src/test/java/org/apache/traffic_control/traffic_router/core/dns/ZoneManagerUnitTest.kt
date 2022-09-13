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
package org.apache.traffic_control.traffic_router.core.dns

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.google.common.cache.*
import org.apache.traffic_control.traffic_router.core.ds.DeliveryService
import org.apache.traffic_control.traffic_router.core.edge.CacheRegister
import org.apache.traffic_control.traffic_router.core.edge.InetRecord
import org.apache.traffic_control.traffic_router.core.request.DNSRequest
import org.apache.traffic_control.traffic_router.core.router.DNSRouteResult
import org.apache.traffic_control.traffic_router.core.router.StatTracker
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import org.apache.traffic_control.traffic_router.core.router.TrafficRouter
import org.apache.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.apache.traffic_control.traffic_router.core.util.TrafficOpsUtils
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.*
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.Mockito
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PowerMockIgnore
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner
import org.xbill.DNS.*
import java.net.*
import java.util.*

@RunWith(PowerMockRunner::class)
@PrepareForTest(ZoneManager::class, SignatureManager::class)
@PowerMockIgnore("javax.management.*")
class ZoneManagerUnitTest {
    var zoneManager: ZoneManager? = null
    var trafficRouter: TrafficRouter? = null
    var signatureManager: SignatureManager? = null
    var cacheRegister: CacheRegister? = null
    @Before
    @Throws(Exception::class)
    fun before() {
        trafficRouter = Mockito.mock(TrafficRouter::class.java)
        cacheRegister = Mockito.mock(CacheRegister::class.java)
        Mockito.`when`(trafficRouter.getCacheRegister()).thenReturn(cacheRegister)
        PowerMockito.spy(ZoneManager::class.java)
        PowerMockito.stub<Any?>(PowerMockito.method(ZoneManager::class.java, "initTopLevelDomain")).toReturn(null)
        PowerMockito.stub<Any?>(PowerMockito.method(ZoneManager::class.java, "initZoneCache")).toReturn(null)
        signatureManager = PowerMockito.mock(SignatureManager::class.java)
        PowerMockito.whenNew(SignatureManager::class.java).withArguments(ArgumentMatchers.any(ZoneManager::class.java), ArgumentMatchers.any(CacheRegister::class.java), ArgumentMatchers.any(TrafficOpsUtils::class.java), ArgumentMatchers.any(TrafficRouterManager::class.java)).thenReturn(signatureManager)
        zoneManager = Mockito.spy(ZoneManager(trafficRouter, StatTracker(), null, Mockito.mock(TrafficRouterManager::class.java)))
    }

    @Test
    @Throws(Exception::class)
    fun itMarksResultTypeAndLocationInDNSAccessRecord() {
        val qname = Name.fromString("edge.www.google.com.")
        val client = InetAddress.getByName("192.168.56.78")
        val setResponse = Mockito.mock(SetResponse::class.java)
        Mockito.`when`(setResponse.isSuccessful).thenReturn(false)
        val zone = Mockito.mock(Zone::class.java)
        Mockito.`when`(zone.findRecords(ArgumentMatchers.any(Name::class.java), ArgumentMatchers.anyInt())).thenReturn(setResponse)
        Mockito.`when`(zone.origin).thenReturn(Name(qname, 1))
        var builder: DNSAccessRecord.Builder? = DNSAccessRecord.Builder(1L, client)
        builder = Mockito.spy(builder)
        Mockito.doReturn(zone).`when`(zoneManager).getZone(qname, Type.A)
        PowerMockito.doCallRealMethod().`when`(zoneManager).getZone(qname, Type.A, client, false, builder)
        zoneManager.getZone(qname, Type.A, client, false, builder)
        Mockito.verify(builder).resultType(ArgumentMatchers.any(ResultType::class.java))
        Mockito.verify(builder).resultLocation(null)
    }

    @Test
    @Throws(Exception::class)
    fun itGetsCorrectNSECRecordFromStaticAndDynamicZones() {
        val qname = Name.fromString("dns1.example.com.")
        val client = InetAddress.getByName("192.168.56.78")
        var builder: DNSAccessRecord.Builder? = DNSAccessRecord.Builder(1L, client)
        builder = Mockito.spy(builder)
        var m_an: Name?
        val m_host: Name?
        val m_admin: Name?
        m_an = Name.fromString("dns1.example.com.")
        m_host = Name.fromString("dns1.example.com.")
        m_admin = Name.fromString("admin.example.com.")
        val ar: Record
        val ns: NSRecord
        val nsec: NSECRecord
        ar = SOARecord(m_an, DClass.IN, 0x13A8,
                m_host, m_admin, 0xABCDEF12L, 0xCDEF1234L,
                0xEF123456L, 0x12345678L, 0x3456789AL)
        ns = NSRecord(m_an, DClass.IN, 12345L, m_an)
        nsec = NSECRecord(m_an, DClass.IN, 12345L, Name("foobar.dns1.example.com."), intArrayOf(1))
        val records = arrayOf<Record?>(ar, ns, nsec)
        m_an = Name.fromString("dns1.example.com.")
        val zone = Zone(m_an, records)
        // static zone
        Mockito.doReturn(zone).`when`(zoneManager).getZone(qname, Type.NSEC)
        val dnsRouteResult = DNSRouteResult()
        val node = JsonNodeFactory.instance.objectNode()
        val domainNode = node.putArray("domains")
        domainNode.add("example.com")
        node.put("routingName", "edge")
        node.put("coverageZoneOnly", false)
        val ds1 = DeliveryService("ds1", node)
        dnsRouteResult.deliveryService = ds1
        val address = InetRecord("cdn-tr.dns1.example.com.", 12345L)
        val list: MutableList<InetRecord?> = ArrayList()
        list.add(address)
        dnsRouteResult.addresses = list
        val cnameRecord: Record = CNAMERecord(Name("dns1.example.com."), DClass.IN, 12345L, Name("cdn-tr.dns1.example.com."))
        val nsecRecord: Record = NSECRecord(Name("edge.dns1.example.com."), DClass.IN, 12345L, Name("foobar.dns1.example.com."), intArrayOf(1))

        // Add records for dynamic zones
        val recordArray = arrayOf<Record?>(cnameRecord, ar, nsecRecord, ns)
        val recordList = Arrays.asList(*recordArray)
        val dynamicZone = Zone(Name("dns1.example.com."), recordArray)
        val loader: CacheLoader<ZoneKey?, Zone?>
        loader = object : CacheLoader<ZoneKey?, Zone?>() {
            override fun load(zoneKey: ZoneKey?): Zone? {
                return dynamicZone
            }
        }
        loader.load(ZoneKey(Name.fromString("dns1.example.com."), Arrays.asList(*records)))
        val dynamicZoneCache = CacheBuilder.newBuilder().build(loader)

        // stub calls for signatureManager, dynamicZoneCache and generateDynamicZoneKey
        Mockito.`when`<LoadingCache<ZoneKey?, Zone?>?>(ZoneManager.Companion.getDynamicZoneCache()).thenReturn(dynamicZoneCache)
        val zk = ZoneKey(Name.fromString("dns1.example.com."), recordList)
        dynamicZoneCache.put(zk, dynamicZone)
        Mockito.`when`<SignatureManager?>(ZoneManager.Companion.getSignatureManager()).thenReturn(signatureManager)
        val currentTimeAnswer = Answer { invocation: InvocationOnMock? -> zk }
        Mockito.`when`<ZoneKey?>(ZoneManager.Companion.getSignatureManager().generateDynamicZoneKey(
                ArgumentMatchers.eq(Name.fromString("dns1.example.com.")),
                ArgumentMatchers.anyList<Record?>(),
                ArgumentMatchers.eq(true))).then(currentTimeAnswer)
        Mockito.`when`(trafficRouter.isEdgeDNSRouting()).thenReturn(true)
        Mockito.`when`(trafficRouter.route(ArgumentMatchers.any(DNSRequest::class.java), ArgumentMatchers.any(StatTracker.Track::class.java))).thenReturn(dnsRouteResult)
        val resultZone = zoneManager.getZone(qname, Type.NSEC, client, true, builder)
        // make sure the function gets called with the correct records as expected
        Mockito.verify<SignatureManager?>(ZoneManager.Companion.getSignatureManager()).generateDynamicZoneKey(ArgumentMatchers.eq(Name.fromString("dns1.example.com.")),
                ArgumentMatchers.argThat { t: MutableList<Record?>? -> t.containsAll(Arrays.asList(nsecRecord, ns, ar)) },
                ArgumentMatchers.eq(true))
        val setResponse = resultZone.findRecords(Name(ds1.routingName + "." + "dns1.example.com."), Type.NSEC)
        MatcherAssert.assertThat(setResponse.isNXDOMAIN, Matchers.equalTo(false))
    }

    @Test
    @Throws(UnknownHostException::class, TextParseException::class)
    fun testZonesAreEqual() {
        internal class TestCase(var reason: String?, var r1: Array<Record?>?, var r2: Array<Record?>?, var expected: Boolean)

        val testCases = arrayOf<TestCase?>(
                TestCase("empty lists are equal", arrayOf(), arrayOf(), true),
                TestCase("different length lists are unequal", arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4"))
                ), arrayOf(), false),
                TestCase("same records but different order lists are equal", arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5"))), arrayOf(
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4"))), true),
                TestCase("same non-empty lists are equal", arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5"))), arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5"))), true),
                TestCase("lists that only differ in the SOA serial number are equal", arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 60, Name("example.com."), Name("example.com."), 1, 60, 1, 1, 1)), arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 60, Name("example.com."), Name("example.com."), 2, 60, 1, 1, 1)), true),
                TestCase("lists that differ in the SOA (other than the serial number) are not equal", arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 60, Name("example.com."), Name("example.com."), 1, 60, 1, 1, 1)), arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 61, Name("example.com."), Name("example.com."), 2, 60, 1, 1, 1)), false),
                TestCase("lists that only differ in NSEC or RRSIG records are equal", arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 60, Name("example.com."), Name("example.com."), 1, 60, 1, 1, 1),
                        NSECRecord(Name("foo.example.com."), DClass.IN, 60, Name("example.com."), intArrayOf(1)),
                        RRSIGRecord(Name("foo.example.com."), DClass.IN, 60, 1, 1, 60, Date(), Date(), 1, Name("example.com."), byteArrayOf(1))
                ), arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 60, Name("example.com."), Name("example.com."), 2, 60, 1, 1, 1)), true),
                TestCase("lists that only differ in NSEC or RRSIG records are equal", arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 60, Name("example.com."), Name("example.com."), 1, 60, 1, 1, 1)), arrayOf(
                        ARecord(Name("foo.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.4")),
                        ARecord(Name("bar.example.com."), DClass.IN, 60, InetAddress.getByName("1.2.3.5")),
                        SOARecord(Name("example.com."), DClass.IN, 60, Name("example.com."), Name("example.com."), 2, 60, 1, 1, 1),
                        NSECRecord(Name("foo.example.com."), DClass.IN, 60, Name("example.com."), intArrayOf(1)),
                        RRSIGRecord(Name("foo.example.com."), DClass.IN, 60, 1, 1, 60, Date(), Date(), 1, Name("example.com."), byteArrayOf(1))
                ), true))
        for (t in testCases) {
            val input1 = Arrays.asList(*t.r1)
            val input2 = Arrays.asList(*t.r2)
            val copy1 = Arrays.asList(*t.r1)
            val copy2 = Arrays.asList(*t.r2)
            val actual: Boolean = ZoneManager.Companion.zonesAreEqual(input1, input2)
            MatcherAssert.assertThat(t.reason, actual, Matchers.equalTo(t.expected))

            // assert that the input lists were not modified
            MatcherAssert.assertThat("zonesAreEqual input lists should not be modified", input1, Matchers.equalTo(copy1))
            MatcherAssert.assertThat("zonesAreEqual input lists should not be modified", input2, Matchers.equalTo(copy2))
        }
    }
}