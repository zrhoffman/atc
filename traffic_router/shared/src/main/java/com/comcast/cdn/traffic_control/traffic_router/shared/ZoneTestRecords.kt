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
package com.comcast.cdn.traffic_control.traffic_router.shared

import com.comcast.cdn.traffic_control.traffic_router.secure.BindPrivateKey
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs1KeySpecDecoder
import org.xbill.DNS.AAAARecord
import org.xbill.DNS.ARecord
import org.xbill.DNS.CNAMERecord
import org.xbill.DNS.DClass
import org.xbill.DNS.DNSKEYRecord
import org.xbill.DNS.DNSSEC
import org.xbill.DNS.NSRecord
import org.xbill.DNS.Name
import org.xbill.DNS.SOARecord
import org.xbill.DNS.TXTRecord
import java.net.Inet6Address
import java.net.InetAddress
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.time.Duration
import java.util.*

object ZoneTestRecords {
    var records: MutableList<Record?>? = null
    var start: Date? = null
    var expiration: Date? = null
    var origin: Name? = null
    var sep_1_2016: Date? = Date(1472688000000L)
    var sep_1_2026: Date? = Date(1788220800000L)
    var zoneSigningKeyRecord: DNSKEYRecord? = null
    var keySigningKeyRecord: DNSKEYRecord? = null
    var ksk1: KeyPair? = null
    var zsk1: KeyPair? = null
    var ksk2: KeyPair? = null
    var zsk2: KeyPair? = null

    @Throws(Exception::class)
    fun generateKeyPairs(): MutableList<KeyPair?>? {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048, SecureRandom.getInstance("SHA1PRNG", "SUN"))
        val keyPairs: MutableList<KeyPair?> = ArrayList()
        keyPairs.add(keyPairGenerator.generateKeyPair())
        keyPairs.add(keyPairGenerator.generateKeyPair())
        keyPairs.add(keyPairGenerator.generateKeyPair())
        keyPairs.add(keyPairGenerator.generateKeyPair())
        return keyPairs
    }

    @Throws(Exception::class)
    private fun recreateKeyPair(publicKey: String?, privateKey: String?): KeyPair? {
        val privateKeyCopy = BindPrivateKey().decode(String(Base64.getMimeDecoder().decode(privateKey)))
        val publicKeyCopy = KeyFactory.getInstance("RSA").generatePublic(Pkcs1KeySpecDecoder().decode(publicKey))
        return KeyPair(publicKeyCopy, privateKeyCopy)
    }

    @Throws(Exception::class)
    fun generateZoneRecords(makeNewKeyPairs: Boolean): MutableList<Record?>? {
        start = Date(System.currentTimeMillis() - 24 * 3600 * 1000)
        expiration = Date(System.currentTimeMillis() + 7 * 24 * 3600 * 1000)
        origin = Name("example.com.")
        val tenYears = Duration.ofDays(3650)
        val oneDay = Duration.ofDays(1)
        val threeDays = Duration.ofDays(3)
        val threeWeeks = Duration.ofDays(21)
        val oneHour: Long = 3600
        val nameServer1 = Name("ns1.example.com.")
        val nameServer2 = Name("ns2.example.com.")
        val adminEmail = Name("admin.example.com.")
        val webServer = Name("www.example.com.")
        val ftpServer = Name("ftp.example.com.")
        val webMirror = Name("mirror.www.example.com.")
        val ftpMirror = Name("mirror.ftp.example.com.")
        val txtRecord: String = String("dead0123456789")
        records = ArrayList<E?>(
            Arrays.asList(
                AAAARecord(webServer, DClass.IN, threeDays.seconds, Inet6Address.getByName("2001:db8::5:6:7:8")),
                AAAARecord(ftpServer, DClass.IN, threeDays.seconds, Inet6Address.getByName("2001:db8::12:34:56:78")),
                NSRecord(origin, DClass.IN, tenYears.seconds, nameServer1),
                NSRecord(origin, DClass.IN, tenYears.seconds, nameServer2),
                ARecord(
                    webServer,
                    DClass.IN,
                    threeWeeks.seconds,
                    InetAddress.getByAddress(byteArrayOf(11, 22, 33, 44))
                ),
                ARecord(
                    webServer,
                    DClass.IN,
                    threeWeeks.seconds,
                    InetAddress.getByAddress(byteArrayOf(55, 66, 77, 88))
                ),
                ARecord(
                    ftpServer,
                    DClass.IN,
                    threeWeeks.seconds,
                    InetAddress.getByAddress(byteArrayOf(12, 34, 56, 78))
                ),
                ARecord(
                    ftpServer,
                    DClass.IN,
                    threeWeeks.seconds,
                    InetAddress.getByAddress(byteArrayOf(21, 43, 65, 87))
                ),
                AAAARecord(webServer, DClass.IN, threeDays.seconds, Inet6Address.getByName("2001:db8::4:3:2:1")),
                SOARecord(
                    origin, DClass.IN, tenYears.seconds, nameServer1,
                    adminEmail, 2016091400L, oneDay.seconds, oneHour, threeWeeks.seconds, threeDays.seconds
                ),
                AAAARecord(ftpServer, DClass.IN, threeDays.seconds, Inet6Address.getByName("2001:db8::21:43:65:87")),
                CNAMERecord(webMirror, DClass.IN, tenYears.seconds, webServer),
                CNAMERecord(ftpMirror, DClass.IN, tenYears.seconds, ftpServer),
                TXTRecord(webServer, DClass.IN, tenYears.seconds, txtRecord)
            )
        )
        if (makeNewKeyPairs) {
            val keyPairs = generateKeyPairs()
            ksk1 = keyPairs.get(0)
            zsk1 = keyPairs.get(1)
            ksk2 = keyPairs.get(2)
            zsk2 = keyPairs.get(3)
        } else {
            ksk1 = recreateKeyPair(SigningData.ksk1Public, SigningData.ksk1Private)
            zsk1 = recreateKeyPair(SigningData.zsk1Public, SigningData.zsk1Private)
            ksk2 = recreateKeyPair(SigningData.ksk2Public, SigningData.ksk2Private)
            zsk2 = recreateKeyPair(SigningData.zsk2Public, SigningData.zsk2Private)
        }
        zoneSigningKeyRecord = DNSKEYRecord(
            origin,
            DClass.IN,
            31556952L,
            DNSKEYRecord.Flags.ZONE_KEY,
            DNSKEYRecord.Protocol.DNSSEC,
            DNSSEC.Algorithm.RSASHA1,
            zsk1.getPublic().encoded
        )
        keySigningKeyRecord = DNSKEYRecord(
            origin,
            DClass.IN,
            315569520L,
            DNSKEYRecord.Flags.ZONE_KEY or DNSKEYRecord.Flags.SEP_KEY,
            DNSKEYRecord.Protocol.DNSSEC,
            DNSSEC.Algorithm.RSASHA1,
            ksk1.getPublic().encoded
        )
        return records
    }
}