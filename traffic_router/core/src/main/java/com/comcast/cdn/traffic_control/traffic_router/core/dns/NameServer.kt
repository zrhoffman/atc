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

import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServer
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.apache.log4j.Logger
import org.xbill.DNS.ClientSubnetOption
import org.xbill.DNS.DClass
import org.xbill.DNS.EDNSOption
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.OPTRecord
import org.xbill.DNS.RRset
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.SOARecord
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import org.xbill.DNS.Zone
import java.net.InetAddress
import java.util.Collections

class NameServer {
    private var ecsEnable = false
    private var ecsEnabledDses: MutableSet<DeliveryService?>? = HashSet()

    /**
     *
     */
    private var trafficRouterManager: TrafficRouterManager? = null

    /**
     * Queries the zones based on the request and returns the appropriate response.
     *
     * @param request
     * the query message
     * @param clientAddress
     * the IP address of the client
     * @return a response message
     */
    fun query(request: Message?, clientAddress: InetAddress?, builder: DNSAccessRecord.Builder?): Message? {
        val response = Message()
        try {
            NameServer.Companion.addQuestion(request, response)
            addAnswers(request, response, clientAddress, builder)
        } catch (e: RuntimeException) {
            NameServer.Companion.LOGGER.error(e.message, e)
            response.header.rcode = Rcode.SERVFAIL
        }
        return response
    }

    private fun addAnswers(
        request: Message?,
        response: Message?,
        clientAddress: InetAddress?,
        builder: DNSAccessRecord.Builder?
    ) {
        val question = request.getQuestion()
        if (question != null) {
            val qclass = question.dClass
            val qname = question.name
            val qopt = request.getOPT()
            var list: MutableList<EDNSOption?>? = Collections.EMPTY_LIST
            var dnssecRequest = false
            var qtype = question.type
            var flags = 0
            if (qopt != null && qopt.version > NameServer.Companion.MAX_SUPPORTED_EDNS_VERS) {
                response.getHeader().rcode = Rcode.NOTIMP
                val opt = OPTRecord(0, Rcode.BADVERS, NameServer.Companion.MAX_SUPPORTED_EDNS_VERS)
                response.addRecord(opt, Section.ADDITIONAL)
                return
            }
            if (qclass != DClass.IN && qclass != DClass.ANY) {
                response.getHeader().rcode = Rcode.REFUSED
                return
            }
            if (qopt != null && qopt.flags and ExtendedFlags.DO != 0) {
                flags = NameServer.Companion.FLAG_DNSSECOK
                dnssecRequest = true
            }
            if (qtype == Type.SIG || qtype == Type.RRSIG) {
                qtype = Type.ANY
                flags = flags or NameServer.Companion.FLAG_SIGONLY
            }
            // Get list of options matching client subnet option code (8)
            if (qopt != null) {
                list = qopt.getOptions(EDNSOption.Code.CLIENT_SUBNET)
            }
            var ipaddr: InetAddress? = null
            var nmask = 0
            if (isEcsEnable(qname)) {
                for (option in list) {
                    assert(option is ClientSubnetOption)
                    // If there are multiple ClientSubnetOptions in the Option RR, then
                    // choose the one with longest source prefix. RFC 7871
                    if ((option as ClientSubnetOption).sourceNetmask > nmask) {
                        nmask = (option as ClientSubnetOption).sourceNetmask
                        ipaddr = (option as ClientSubnetOption).address
                    }
                }
            }
            if (ipaddr != null && isEcsEnable(qname)) {
                builder.client(ipaddr)
                NameServer.Companion.LOGGER.debug(
                    "DNS: Using Client IP Address from ECS Option" + ipaddr.hostAddress + "/"
                            + nmask
                )
                lookup(qname, qtype, ipaddr, response, flags, dnssecRequest, builder)
            } else {
                lookup(qname, qtype, clientAddress, response, flags, dnssecRequest, builder)
            }
            if (response.getHeader().rcode == Rcode.REFUSED) {
                return
            }

            // Check if we had incoming ClientSubnetOption in Option RR, then we need
            // to return with the response, setting the scope subnet as well
            if (nmask != 0 && isEcsEnable(qname)) {
                val cso = ClientSubnetOption(nmask, nmask, ipaddr)
                val csoList: MutableList<ClientSubnetOption?> = ArrayList(1)
                csoList.add(cso)
                // OptRecord Arguments: payloadSize = 1280, xrcode = 0, version=0, flags=0, option List
                val opt = OPTRecord(1280, 0, 0, 0, csoList)
                response.addRecord(opt, Section.ADDITIONAL)
            }
            if (qopt != null && flags == NameServer.Companion.FLAG_DNSSECOK) {
                val optflags = ExtendedFlags.DO
                val opt = OPTRecord(1280, 0 as Byte, 0 as Byte, optflags)
                response.addRecord(opt, Section.ADDITIONAL)
            }
        }
    }

    private fun isDeliveryServiceEcsEnabled(name: Name?): Boolean {
        var isEnabled = false
        for (ds in ecsEnabledDses) {
            var domain: String = ds.getDomain() ?: continue
            if (domain.endsWith("+")) {
                domain = domain.replace("\\+\\z".toRegex(), ".") + ZoneManager.Companion.getTopLevelDomain()
            }
            if (name.relativize(Name.root).toString().contains(domain)) {
                isEnabled = true
                break
            }
        }
        return isEnabled
    }

    private fun lookup(
        qname: Name?,
        qtype: Int,
        clientAddress: InetAddress?,
        response: Message?,
        flags: Int,
        dnssecRequest: Boolean,
        builder: DNSAccessRecord.Builder?
    ) {
        lookup(qname, qtype, clientAddress, null, response, 0, flags, dnssecRequest, builder)
    }

    private fun lookup(
        qname: Name?,
        qtype: Int,
        clientAddress: InetAddress?,
        incomingZone: Zone?,
        response: Message?,
        iteration: Int,
        flags: Int,
        dnssecRequest: Boolean,
        builder: DNSAccessRecord.Builder?
    ) {
        if (iteration > NameServer.Companion.MAX_ITERATIONS) {
            return
        }
        var zone = incomingZone

        // this allows us to locate zones for which we are authoritative
        if (zone == null || !qname.subdomain(zone.origin)) {
            zone = trafficRouterManager.getTrafficRouter().getZone(qname, qtype, clientAddress, dnssecRequest, builder)
        }

        // null means we did not find a zone for which we are authoritative
        if (zone == null) {
            if (iteration == 0) {
                // refuse the query if we're not authoritative and we're not recursing
                response.getHeader().rcode = Rcode.REFUSED
            }
            return
        }
        val sr = zone.findRecords(qname, qtype)
        if (sr.isSuccessful) {
            for (answer in sr.answers()) {
                NameServer.Companion.addRRset(qname, response, answer, Section.ANSWER, flags)
            }
            NameServer.Companion.addAuthority(zone, response, flags)
        } else if (sr.isCNAME) {
            /*
			 * This is an ugly hack to work around the answers() method not working for CNAMEs.
			 * A CNAME results in isSuccessful() being false, and answers() requires isSuccessful()
			 * to be true. Because of this, we can either use reflection (slow) or use the getNS() method, which
			 * returns the RRset stored internally in "data" and is not actually specific to NS records.
			 * Our CNAME and RRSIGs are in this RRset, so use getNS() despite its name.
			 * Refer to the dnsjava SetResponse code for more information.
			 */
            val rrset = sr.ns
            NameServer.Companion.addRRset(qname, response, rrset, Section.ANSWER, flags)

            /*
			 * Allow recursive lookups for CNAME targets; the logic above allows us to
			 * ensure that we only recurse for domains for which we are authoritative.
			 */lookup(
                sr.cname.target,
                qtype,
                clientAddress,
                zone,
                response,
                iteration + 1,
                flags,
                dnssecRequest,
                builder
            )
        } else if (sr.isNXDOMAIN) {
            response.getHeader().rcode = Rcode.NXDOMAIN
            response.getHeader().setFlag(Flags.AA.toInt())
            NameServer.Companion.addDenialOfExistence(qname, zone, response, flags)
            NameServer.Companion.addSOA(zone, response, Section.AUTHORITY, flags)
        } else if (sr.isNXRRSET) {
            /*
			 * Per RFC 2308 NODATA is inferred by having no records;
			 * NXRRSET is discussed in RFC 2136, but that RFC is for Dynamic DNS updates.
			 * We'll ignore the NXRRSET from the API, and allow the client resolver to
			 * deal with NODATA per RFC 2308:
			 *   "NODATA" - a pseudo RCODE which indicates that the name is valid, for
			 *   the given class, but are no records of the given type.
			 *   A NODATA response has to be inferred from the answer.
			 */

            // The requirements for this are described in RFC 7129
            if (flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) != 0) {
                val ndsr = zone.findRecords(qname, Type.NSEC)
                if (ndsr.isSuccessful) {
                    for (answer in ndsr.answers()) {
                        NameServer.Companion.addRRset(qname, response, answer, Section.AUTHORITY, flags)
                    }
                }
            }
            NameServer.Companion.addSOA(zone, response, Section.AUTHORITY, flags)
            response.getHeader().setFlag(Flags.AA.toInt())
        }
    }

    fun getTrafficRouterManager(): TrafficRouterManager? {
        return trafficRouterManager
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    fun destroy() {
        /*
		 * Yes, this is odd. We need to call destroy on ZoneManager, but it's static, so
		 * we don't have a Spring bean ref; we do for NameServer, so this method is called.
		 * Given that we know we're shutting down and NameServer relies on ZoneManager,
		 * we'll call destroy while we can without hacking Spring too hard.
		 */
        ZoneManager.Companion.destroy()
    }

    fun isEcsEnable(qname: Name?): Boolean {
        return ecsEnable || isDeliveryServiceEcsEnabled(qname)
    }

    fun setEcsEnable(ecsEnable: Boolean) {
        this.ecsEnable = ecsEnable
    }

    fun getEcsEnabledDses(): MutableSet<DeliveryService?>? {
        return ecsEnabledDses
    }

    fun setEcsEnabledDses(ecsEnabledDses: MutableSet<DeliveryService?>?) {
        this.ecsEnabledDses = ecsEnabledDses
    }

    companion object {
        private const val MAX_SUPPORTED_EDNS_VERS = 0
        private const val MAX_ITERATIONS = 6
        private const val NUM_SECTIONS = 4
        private const val FLAG_DNSSECOK = 1
        private const val FLAG_SIGONLY = 2
        private val LOGGER = Logger.getLogger(NameServer::class.java)
        private fun addAuthority(zone: Zone?, response: Message?, flags: Int) {
            val authority = zone.getNS()
            NameServer.Companion.addRRset(authority.name, response, authority, Section.AUTHORITY, flags)
            response.getHeader().setFlag(Flags.AA.toInt())
        }

        private fun addSOA(zone: Zone?, response: Message?, section: Int, flags: Int) {
            // we locate the SOA this way so that we can ensure we get the RRSIGs rather than just the one SOA Record
            val fsoa = zone.findRecords(zone.getOrigin(), Type.SOA)
            if (!fsoa.isSuccessful) {
                return
            }
            for (answer in fsoa.answers()) {
                NameServer.Companion.addRRset(
                    zone.getOrigin(),
                    response,
                    NameServer.Companion.setNegativeTTL(answer, flags),
                    section,
                    flags
                )
            }
        }

        private fun addDenialOfExistence(qname: Name?, zone: Zone?, response: Message?, flags: Int) {
            // The requirements for this are described in RFC 7129
            if (flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) == 0) {
                return
            }
            var nsecSpan: RRset? = null
            var candidate: Name? = null
            val zi: MutableIterator<RRset?>? = zone.iterator()
            while (zi.hasNext()) {
                val rrset = zi.next()
                if (rrset.getType() != Type.NSEC) {
                    continue
                }
                val it: MutableIterator<Record?>? = rrset.rrs()
                while (it.hasNext()) {
                    val r = it.next()
                    val name = r.getName()
                    if (name.compareTo(qname) < 0 || candidate != null && name.compareTo(candidate) < 0) {
                        candidate = name
                        nsecSpan = rrset
                    } else if (name.compareTo(qname) > 0 && candidate != null) {
                        break
                    }
                }
            }
            if (candidate != null && nsecSpan != null) {
                NameServer.Companion.addRRset(candidate, response, nsecSpan, Section.AUTHORITY, flags)
            }
            val nxsr = zone.findRecords(zone.getOrigin(), Type.NSEC)
            if (nxsr.isSuccessful) {
                for (answer in nxsr.answers()) {
                    NameServer.Companion.addRRset(qname, response, answer, Section.AUTHORITY, flags)
                }
            }
        }

        private fun addQuestion(request: Message?, response: Message?) {
            response.getHeader().id = request.getHeader().id
            response.getHeader().setFlag(Flags.QR.toInt())
            if (request.getHeader().getFlag(Flags.RD.toInt())) {
                response.getHeader().setFlag(Flags.RD.toInt())
            }
            response.addRecord(request.getQuestion(), Section.QUESTION)
        }

        private fun addRRset(name: Name?, response: Message?, rrset: RRset?, section: Int, flags: Int) {
            for (s in 1 until NameServer.Companion.NUM_SECTIONS) {
                if (response.findRRset(name, rrset.getType(), s)) {
                    return
                }
            }
            val recordList: MutableList<Record?> = ArrayList()
            if (flags and NameServer.Companion.FLAG_SIGONLY == 0) {
                val it: MutableIterator<Record?>? = rrset.rrs()
                while (it.hasNext()) {
                    var r = it.next()
                    if (r.getName().isWild && !name.isWild()) {
                        r = r.withName(name)
                    }
                    recordList.add(r)
                }
            }

            // We prefer to shuffle the list over "cycling" as we could with rrset.rrs(true) above.
            Collections.shuffle(recordList)
            for (r in recordList) {
                response.addRecord(r, section)
            }
            if (flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) != 0) {
                val it: MutableIterator<Record?>? = rrset.sigs()
                while (it.hasNext()) {
                    var r = it.next()
                    if (r.getName().isWild && !name.isWild()) {
                        r = r.withName(name)
                    }
                    response.addRecord(r, section)
                }
            }
        }

        private fun setNegativeTTL(original: RRset?, flags: Int): RRset? {
            /*
		 * If DNSSEC is enabled/requested, use the SOA and sigs, otherwise
		 * lower the TTL on the SOA record to the minimum/ncache TTL,
		 * using whichever is lower. Behavior is defined in RFC 2308.
		 * In practice we see Vantio using the minimum from the SOA, while BIND
		 * uses the lowest TTL in the RRset in the authority section. When DNSSEC
		 * is enabled, the TTL for the RRsigs is derived from the minimum of the
		 * SOA via the jdnssec library, hence only modifying the TTL of the SOA
		 * itself in the non-DNSSEC use case below. We would invalidate the existing
		 * RRsigs if we modified the TTL of a signed RRset.
		 */

            // signed RRset and DNSSEC requested; return unmodified
            if (original.sigs()
                    .hasNext() && flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) != 0
            ) {
                return original
            }
            val rrset = RRset()
            val it: MutableIterator<Record?>? = original.rrs()
            while (it.hasNext()) {
                var record = it.next()
                if (record is SOARecord) {
                    val soa = record as SOARecord?

                    // the value of the minimum field is less than the actual TTL; adjust
                    if (soa.getMinimum() != 0L || soa.getTTL() > soa.getMinimum()) {
                        record = SOARecord(
                            soa.getName(), DClass.IN, soa.getMinimum(), soa.getHost(), soa.getAdmin(),
                            soa.getSerial(), soa.getRefresh(), soa.getRetry(), soa.getExpire(),
                            soa.getMinimum()
                        )
                    } // else use the unmodified record
                }
                rrset.addRR(record)
            }
            return rrset
        }
    }
}