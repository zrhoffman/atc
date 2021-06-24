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

import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger
import org.xbill.DNS.Record
import java.text.SimpleDateFormat
import java.util.*

object ZoneUtils {
    private val LOGGER = Logger.getLogger(ZoneUtils::class.java)
    private val sdf: SimpleDateFormat? = SimpleDateFormat("yyyyMMddHH")
    fun getMaximumTTL(records: MutableList<Record?>?): Long {
        var maximumTTL: Long = 0
        for (record in records) {
            if (record.getTTL() > maximumTTL) {
                maximumTTL = record.getTTL()
            }
        }
        return maximumTTL
    }

    fun getSerial(jo: JsonNode?): Long {
        synchronized(ZoneUtils.sdf) {
            var date: Date? = null
            if (jo != null && jo.has("date")) {
                try {
                    val cal = Calendar.getInstance()
                    cal.timeInMillis = JsonUtils.getLong(jo, "date") * 1000
                    date = cal.time
                } catch (ex: JsonUtilsException) {
                    ZoneUtils.LOGGER.error(ex, ex)
                }
            }
            if (date == null) {
                date = Date()
            }
            return ZoneUtils.sdf.format(date).toLong() // 2013062701
        }
    }

    fun getLong(jo: JsonNode?, key: String?, d: Long): Long {
        if (jo == null) {
            return d
        }
        return if (jo.has(key)) jo[key].asLong(d) else d
    }

    fun getAdminString(jo: JsonNode?, key: String?, d: String?, domain: String?): String? {
        if (jo == null) {
            return StringBuffer(d).append(".").append(domain).toString()
        }
        if (!jo.has(key)) {
            return StringBuffer(d).append(".").append(domain).toString()
        }

        // check for @ sign in string
        var admin = if (jo.has(key)) jo[key].asText() else ""
        admin = if (admin.contains("@")) {
            admin.replace("@", ".")
        } else {
            StringBuffer(admin).append(".").append(domain).toString()
        }
        return admin
    }
}