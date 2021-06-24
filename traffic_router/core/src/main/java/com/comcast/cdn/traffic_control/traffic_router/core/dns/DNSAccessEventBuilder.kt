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

import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import org.xbill.DNS.WireParseException
import java.math.RoundingMode
import java.text.DecimalFormat

object DNSAccessEventBuilder {
    fun create(dnsAccessRecord: DNSAccessRecord?): String? {
        val event = DNSAccessEventBuilder.createEvent(dnsAccessRecord)
        var rType = "-"
        var rdtl = "-"
        var rloc = "-"
        if (dnsAccessRecord.getResultType() != null) {
            rType = dnsAccessRecord.getResultType().toString()
            if (dnsAccessRecord.getResultDetails() != null) {
                rdtl = dnsAccessRecord.getResultDetails().toString()
            }
        }
        if (dnsAccessRecord.getResultLocation() != null) {
            val resultLocation = dnsAccessRecord.getResultLocation()
            val decimalFormat = DecimalFormat(".##")
            decimalFormat.roundingMode = RoundingMode.DOWN
            rloc = decimalFormat.format(resultLocation.latitude) + "," + decimalFormat.format(resultLocation.longitude)
        }
        val routingInfo = "rtype=$rType rloc=\"$rloc\" rdtl=$rdtl rerr=\"-\""
        var answer: String? = "ans=\"-\""
        if (dnsAccessRecord.getDnsMessage() != null) {
            answer = DNSAccessEventBuilder.createTTLandAnswer(dnsAccessRecord.getDnsMessage())
        }
        return "$event $routingInfo $answer"
    }

    private fun createEvent(dnsAccessRecord: DNSAccessRecord?): String? {
        val timeString =
            String.format("%d.%03d", dnsAccessRecord.getQueryInstant() / 1000, dnsAccessRecord.getQueryInstant() % 1000)
        val ttms = (System.nanoTime() - dnsAccessRecord.getRequestNanoTime()) / 1000000.0
        val clientAddressString = dnsAccessRecord.getClient().hostAddress
        val resolverAddressString = dnsAccessRecord.getResolver().hostAddress
        val stringBuilder =
            StringBuilder(timeString).append(" qtype=DNS chi=").append(clientAddressString).append(" rhi=")
        if (clientAddressString != resolverAddressString) {
            stringBuilder.append(resolverAddressString)
        } else {
            stringBuilder.append('-')
        }
        stringBuilder.append(" ttms=").append(String.format("%.03f", ttms))
        if (dnsAccessRecord.getDnsMessage() == null) {
            return stringBuilder.append(" xn=- fqdn=- type=- class=- rcode=-").toString()
        }
        val messageHeader = DNSAccessEventBuilder.createDnsMessageHeader(dnsAccessRecord.getDnsMessage())
        return stringBuilder.append(messageHeader).toString()
    }

    private fun createDnsMessageHeader(dnsMessage: Message?): String? {
        val queryHeader = " xn=" + dnsMessage.getHeader().id
        val query = " " + DNSAccessEventBuilder.createQuery(dnsMessage.getQuestion())
        val rcode = " rcode=" + Rcode.string(dnsMessage.getHeader().rcode)
        return StringBuilder(queryHeader).append(query).append(rcode).toString()
    }

    private fun createTTLandAnswer(dnsMessage: Message?): String? {
        if (dnsMessage.getSectionArray(Section.ANSWER) == null || dnsMessage.getSectionArray(Section.ANSWER).size == 0) {
            return "ttl=\"-\" ans=\"-\""
        }
        val answerStringBuilder = StringBuilder()
        val ttlStringBuilder = StringBuilder()
        for (record in dnsMessage.getSectionArray(Section.ANSWER)) {
            val s = record.rdataToString() + " "
            val ttl = record.ttl.toString() + " "
            answerStringBuilder.append(s)
            ttlStringBuilder.append(ttl)
        }
        return "ttl=\"" + ttlStringBuilder.toString().trim { it <= ' ' } + "\" ans=\"" + answerStringBuilder.toString()
            .trim { it <= ' ' } + "\""
    }

    fun create(dnsAccessRecord: DNSAccessRecord?, wireParseException: WireParseException?): String? {
        val event = DNSAccessEventBuilder.createEvent(dnsAccessRecord)
        val rerr = "Bad Request:" + wireParseException.javaClass.simpleName + ":" + wireParseException.message
        return StringBuilder(event)
            .append(" rtype=-")
            .append(" rloc=\"-\"")
            .append(" rdtl=-")
            .append(" rerr=\"")
            .append(rerr)
            .append("\"")
            .append(" ttl=\"-\"")
            .append(" ans=\"-\"")
            .toString()
    }

    fun create(dnsAccessRecord: DNSAccessRecord?, exception: Exception?): String? {
        val dnsMessage = dnsAccessRecord.getDnsMessage()
        dnsMessage.header.rcode = Rcode.SERVFAIL
        val event = DNSAccessEventBuilder.createEvent(dnsAccessRecord)
        val rerr = "Server Error:" + exception.javaClass.simpleName + ":" + exception.message
        return StringBuilder(event)
            .append(" rtype=-")
            .append(" rloc=\"-\"")
            .append(" rdtl=-")
            .append(" rerr=\"")
            .append(rerr)
            .append("\"")
            .append(" ttl=\"-\"")
            .append(" ans=\"-\"").toString()
    }

    private fun createQuery(query: Record?): String? {
        if (query != null && query.name != null) {
            val qname = query.name.toString()
            val qtype = Type.string(query.type)
            val qclass = DClass.string(query.dClass)
            return StringBuilder()
                .append("fqdn=").append(qname)
                .append(" type=").append(qtype)
                .append(" class=").append(qclass)
                .toString()
        }
        return ""
    }
}