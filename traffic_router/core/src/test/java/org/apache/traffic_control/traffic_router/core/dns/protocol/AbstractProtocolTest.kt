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
package org.apache.traffic_control.traffic_router.core.dns.protocol

import org.apache.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import org.apache.traffic_control.traffic_router.core.dns.DNSAccessRecord
import org.apache.traffic_control.traffic_router.core.dns.NameServer
import org.apache.traffic_control.traffic_router.core.dns.protocol.AbstractProtocolTest.FakeAbstractProtocol
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
import java.net.Inet4Address
import java.net.InetAddress

org.apache.logging.log4j.LogManagerimport org.apache.logging.log4j.Logger
import org.apache.tomcat.util.net.SSLImplementation
import org.apache.tomcat.util.net.SSLSupport
import org.apache.tomcat.util.net.jsse.JSSESupport
import org.apache.tomcat.util.net.SSLUtil
import secure.KeyManagerTest.TestSNIServerName
import secure.CertificateDataConverterTest
import org.apache.traffic_control.traffic_router.protocol.RouterSslImplementationimport

org.junit.*import org.xbill.DNS.*
import java.lang.Exceptionimport

java.lang.Recordimport java.util.*
@RunWith(PowerMockRunner::class)
@PrepareForTest(FakeAbstractProtocol::class, Logger::class, LogManager::class, DNSAccessEventBuilder::class, Header::class, NameServer::class, DNSAccessRecord::class)
@PowerMockIgnore("javax.management.*")
class AbstractProtocolTest {
    private var nameServer: NameServer? = null
    private var header: Header? = null
    var client: InetAddress? = null
    @Before
    @Throws(Exception::class)
    fun before() {
        // force the xn field in the request
        val random = Mockito.mock(Random::class.java)
        Mockito.`when`(random.nextInt(0xffff)).thenReturn(65535)
        PowerMockito.whenNew(Random::class.java).withNoArguments().thenReturn(random)
        PowerMockito.mockStatic(System::class.java)
        val nanoTimeAnswer: Answer<Long?> = object : Answer<Long?>() {
            val nanoTimes: LongArray? = longArrayOf(100000000L, 100000000L + 345123000L)
            var index = 0
            override fun answer(invocation: InvocationOnMock?): Long? {
                return nanoTimes.get(index++ % 2)
            }
        }
        PowerMockito.`when`(System.nanoTime()).thenAnswer(nanoTimeAnswer)
        val currentTimeAnswer: Answer<Long?> = object : Answer<Long?>() {
            val currentTimes: LongArray? = longArrayOf(144140678000L, 144140678345L)
            var index = 0
            override fun answer(invocation: InvocationOnMock?): Long? {
                return currentTimes.get(index++ % 2)
            }
        }
        PowerMockito.`when`(System.currentTimeMillis()).then(currentTimeAnswer)
        PowerMockito.mockStatic(LogManager::class.java)
        PowerMockito.`when`(LogManager.getLogger("org.apache.traffic_control.traffic_router.core.access")).thenAnswer { invocation: InvocationOnMock? -> accessLogger }
        header = Header()
        header.setID(65535)
        header.setFlag(Flags.QR.toInt())
        client = Inet4Address.getByAddress(byteArrayOf(192.toByte(), 168.toByte(), 23, 45))
        nameServer = Mockito.mock(NameServer::class.java)
    }

    @Test
    @Throws(Exception::class)
    fun itLogsARecordQueries() {
        header.setRcode(Rcode.NOERROR)
        val name = Name.fromString("www.example.com.")
        val question: Record = Record.newRecord(name, Type.A, DClass.IN, 0L)
        val query = Message.newQuery(question)
        query.header.rcode
        val queryBytes = query.toWire()
        PowerMockito.whenNew(Message::class.java).withArguments(queryBytes).thenReturn(query)
        val resolvedAddress = Inet4Address.getByName("192.168.8.9")
        val answer: Record = ARecord(name, DClass.IN, 3600L, resolvedAddress)
        val answers = arrayOf<Record?>(answer)
        val response = Mockito.mock(Message::class.java)
        PowerMockito.`when`(response.header).thenReturn(header)
        PowerMockito.`when`(response.getSectionArray(Section.ANSWER)).thenReturn(answers)
        PowerMockito.`when`(response.question).thenReturn(question)
        val client = Inet4Address.getByName("192.168.23.45")
        PowerMockito.`when`(nameServer.query(ArgumentMatchers.any(Message::class.java), ArgumentMatchers.any(InetAddress::class.java), ArgumentMatchers.any(DNSAccessRecord.Builder::class.java))).thenReturn(response)
        val abstractProtocol = FakeAbstractProtocol(client, queryBytes)
        abstractProtocol.nameServer = nameServer
        abstractProtocol.run()
        Mockito.verify(accessLogger).info("144140678.000 qtype=DNS chi=192.168.23.45 rhi=- ttms=345.123 xn=65535 fqdn=www.example.com. type=A class=IN rcode=NOERROR rtype=- rloc=\"-\" rdtl=- rerr=\"-\" ttl=\"3600\" ans=\"192.168.8.9\" svc=\"-\"")
    }

    @Test
    @Throws(Exception::class)
    fun itLogsOtherQueries() {
        header.setRcode(Rcode.REFUSED)
        val name = Name.fromString("John Wayne.")
        val question: Record = Record.newRecord(name, 65530, 43210)
        val query = Message.newQuery(question)
        val response = Mockito.mock(Message::class.java)
        PowerMockito.`when`(response.header).thenReturn(header)
        PowerMockito.`when`(response.getSectionArray(Section.ANSWER)).thenReturn(null)
        PowerMockito.`when`(response.question).thenReturn(question)
        PowerMockito.`when`(nameServer.query(ArgumentMatchers.any(Message::class.java), ArgumentMatchers.any(InetAddress::class.java), ArgumentMatchers.any(DNSAccessRecord.Builder::class.java))).thenReturn(response)
        val abstractProtocol = FakeAbstractProtocol(client, query.toWire())
        abstractProtocol.nameServer = nameServer
        abstractProtocol.run()
        Mockito.verify(accessLogger).info("144140678.000 qtype=DNS chi=192.168.23.45 rhi=- ttms=345.123 xn=65535 fqdn=John\\032Wayne. type=TYPE65530 class=CLASS43210 rcode=REFUSED rtype=- rloc=\"-\" rdtl=- rerr=\"-\" ttl=\"-\" ans=\"-\" svc=\"-\"")
    }

    @Test
    @Throws(Exception::class)
    fun itLogsBadClientRequests() {
        val abstractProtocol = FakeAbstractProtocol(client, byteArrayOf(1, 2, 3, 4, 5, 6, 7))
        abstractProtocol.nameServer = nameServer
        abstractProtocol.run()
        Mockito.verify(accessLogger).info("144140678.000 qtype=DNS chi=192.168.23.45 rhi=- ttms=345.123 xn=- fqdn=- type=- class=- rcode=- rtype=- rloc=\"-\" rdtl=- rerr=\"Bad Request:WireParseException:end of input\" ttl=\"-\" ans=\"-\" svc=\"-\"")
    }

    @Test
    @Throws(Exception::class)
    fun itLogsServerErrors() {
        header.setRcode(Rcode.REFUSED)
        val name = Name.fromString("John Wayne.")
        val question: Record = Record.newRecord(name, 65530, 43210)
        val query = Message.newQuery(question)
        val response = Mockito.mock(Message::class.java)
        PowerMockito.`when`(response.header).thenReturn(header)
        PowerMockito.`when`(response.getSectionArray(Section.ANSWER)).thenReturn(null)
        PowerMockito.`when`(response.question).thenReturn(question)
        PowerMockito.`when`(nameServer.query(ArgumentMatchers.any(Message::class.java), ArgumentMatchers.any(InetAddress::class.java), ArgumentMatchers.any(DNSAccessRecord.Builder::class.java))).thenThrow(RuntimeException("Aw snap!"))
        val abstractProtocol = FakeAbstractProtocol(client, query.toWire())
        abstractProtocol.nameServer = nameServer
        abstractProtocol.run()
        Mockito.verify(accessLogger).info("144140678.000 qtype=DNS chi=192.168.23.45 rhi=- ttms=345.123 xn=65535 fqdn=John\\032Wayne. type=TYPE65530 class=CLASS43210 rcode=SERVFAIL rtype=- rloc=\"-\" rdtl=- rerr=\"Server Error:RuntimeException:Aw snap!\" ttl=\"-\" ans=\"-\" svc=\"-\"")
    }

    inner class FakeAbstractProtocol(private val inetAddress: InetAddress?, private val request: ByteArray?) : AbstractProtocol() {
        override fun getMaxResponseLength(request: Message?): Int {
            return Int.MAX_VALUE
        }

        override fun run() {
            try {
                query(inetAddress, request)
            } catch (e: WireParseException) {
                // Ignore it
            }
        }
    }

    companion object {
        private val accessLogger = Mockito.mock(Logger::class.java)
    }
}