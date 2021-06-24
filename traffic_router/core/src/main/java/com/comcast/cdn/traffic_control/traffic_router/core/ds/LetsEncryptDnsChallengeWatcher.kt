package com.comcast.cdn.traffic_control.traffic_router.core.ds

import com.comcast.cdn.traffic_control.traffic_router.core.config.ConfigHandler
import com.comcast.cdn.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallengeWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.ObjectNode
import org.apache.log4j.Logger
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.time.Instant
import java.util.function.Consumer

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
 */   class LetsEncryptDnsChallengeWatcher : AbstractResourceWatcher() {
    private var configFile: String? = null
    private var configHandler: ConfigHandler? = null
    public override fun useData(data: String?): Boolean {
        try {
            val mapper = ObjectMapper(JsonFactory())
            val dataMap = mapper.readValue(
                data,
                object : TypeReference<HashMap<String?, MutableList<LetsEncryptDnsChallenge?>?>?>() {})
            val challengeList = dataMap["response"]
            val mostRecentConfig = mapper.readTree(readConfigFile())
            val deliveryServicesNode =
                JsonUtils.getJsonNode(mostRecentConfig, ConfigHandler.Companion.deliveryServicesKey) as ObjectNode
            challengeList.forEach(Consumer { challenge: LetsEncryptDnsChallenge? ->
                val sb = StringBuilder()
                sb.append(challenge.getFqdn())
                if (!challenge.getFqdn().endsWith(".")) {
                    sb.append('.')
                }
                val challengeDomain = sb.toString()
                val fqdn = challengeDomain.substring(0, challengeDomain.length - 1).replace("_acme-challenge.", "")
                var deliveryServiceConfig: ObjectNode? = null
                var dsLabel: String? = ""
                val nameSb = StringBuilder()
                nameSb.append("_acme-challenge")
                for (label in fqdn.split("\\.".toRegex()).toTypedArray()) {
                    deliveryServiceConfig = deliveryServicesNode[label] as ObjectNode
                    if (deliveryServiceConfig != null) {
                        dsLabel = label
                        break
                    } else {
                        nameSb.append('.')
                        nameSb.append(label)
                    }
                }
                val name = nameSb.toString()
                val staticDnsEntriesNode = updateStaticEntries(challenge, name, mapper, deliveryServiceConfig)
                deliveryServiceConfig.set<JsonNode?>("staticDnsEntries", staticDnsEntriesNode)
                deliveryServicesNode.set<JsonNode?>(dsLabel, deliveryServiceConfig)
            })
            val statsNode = mostRecentConfig["stats"] as ObjectNode
            statsNode.put("date", Instant.now().toEpochMilli() / 1000L)
            val fullConfig = mostRecentConfig as ObjectNode
            fullConfig.set<JsonNode?>(ConfigHandler.Companion.deliveryServicesKey, deliveryServicesNode)
            fullConfig.set<JsonNode?>("stats", statsNode)
            try {
                configHandler.processConfig(fullConfig.toString())
            } catch (jsonError: JsonParseException) {
                LetsEncryptDnsChallengeWatcher.Companion.LOGGER.error("error processing config: " + jsonError.message)
            } catch (jsonError: JsonUtilsException) {
                LetsEncryptDnsChallengeWatcher.Companion.LOGGER.error("error processing config: " + jsonError.message)
            }
            return true
        } catch (e: Exception) {
            LetsEncryptDnsChallengeWatcher.Companion.LOGGER.warn(
                "Failed updating dns challenge txt record with data from $dataBaseURL:",
                e
            )
        }
        return false
    }

    override fun verifyData(data: String?): Boolean {
        try {
            val mapper = ObjectMapper(JsonFactory())
            mapper.readValue(
                data,
                object : TypeReference<HashMap<String?, MutableList<LetsEncryptDnsChallenge?>?>?>() {})
            return true
        } catch (e: Exception) {
            LetsEncryptDnsChallengeWatcher.Companion.LOGGER.warn(
                "Failed to build dns challenge data while verifying:",
                e
            )
        }
        return false
    }

    override fun getWatcherConfigPrefix(): String? {
        return "dnschallengemapping"
    }

    private fun readConfigFile(): String? {
        return try {
            val `is`: InputStream = FileInputStream(databasesDirectory.resolve(configFile).toString())
            val buf = BufferedReader(InputStreamReader(`is`))
            var line = buf.readLine()
            val sb = StringBuilder()
            while (line != null) {
                sb.append(line).append('\n')
                line = buf.readLine()
            }
            sb.toString()
        } catch (e: Exception) {
            LetsEncryptDnsChallengeWatcher.Companion.LOGGER.error("Could not read cr-config file $configFile:", e)
            null
        }
    }

    private fun updateStaticEntries(
        challenge: LetsEncryptDnsChallenge?,
        name: String?,
        mapper: ObjectMapper?,
        deliveryServiceConfig: ObjectNode?
    ): ArrayNode? {
        var staticDnsEntriesNode = mapper.createArrayNode()
        var newStaticDnsEntriesNode = mapper.createArrayNode()
        if (deliveryServiceConfig.findValue("staticDnsEntries") != null) {
            staticDnsEntriesNode = deliveryServiceConfig.findValue("staticDnsEntries") as ArrayNode
        }
        if (challenge.getRecord().isEmpty()) {
            for (i in 0 until staticDnsEntriesNode.size()) {
                if (staticDnsEntriesNode[i]["name"] != name) {
                    newStaticDnsEntriesNode.add(i)
                }
            }
        } else {
            newStaticDnsEntriesNode = staticDnsEntriesNode
            val newChildNode = mapper.createObjectNode()
            newChildNode.put("type", "TXT")
            newChildNode.put("name", name)
            newChildNode.put("value", challenge.getRecord())
            newChildNode.put("ttl", 10)
            newStaticDnsEntriesNode.add(newChildNode)
        }
        return newStaticDnsEntriesNode
    }

    fun setConfigHandler(configHandler: ConfigHandler?) {
        this.configHandler = configHandler
    }

    fun getConfigHandler(): ConfigHandler? {
        return configHandler
    }

    fun setConfigFile(configFile: String?) {
        this.configFile = configFile
    }

    companion object {
        private val LOGGER = Logger.getLogger(
            LetsEncryptDnsChallengeWatcher::class.java
        )
        val DEFAULT_LE_DNS_CHALLENGE_URL: String? = "https://\${toHostname}/api/2.0/letsencrypt/dnsrecords/"
    }

    init {
        setDatabaseUrl(LetsEncryptDnsChallengeWatcher.Companion.DEFAULT_LE_DNS_CHALLENGE_URL)
        setDefaultDatabaseUrl(LetsEncryptDnsChallengeWatcher.Companion.DEFAULT_LE_DNS_CHALLENGE_URL)
    }
}