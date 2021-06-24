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
package com.comcast.cdn.traffic_control.traffic_router.api.controllers

import com.comcast.cdn.traffic_control.traffic_router.core.util.DataExporter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody

@Controller
@RequestMapping("/stats")
class StatsController {
    @Autowired
    private val dataExporter: DataExporter? = null

    @GetMapping
    @ResponseBody
    fun getStats(): MutableMap<String?, Any?>? {
        val map: MutableMap<String?, Any?> = HashMap()
        map["app"] = dataExporter.getAppInfo()
        map["stats"] = dataExporter.getStatTracker()
        return map
    }

    @GetMapping(value = ["/ip/{ip:.+}"])
    @ResponseBody
    fun getCaches(
        @PathVariable("ip") ip: String?,
        @RequestParam(
            name = "geolocationProvider",
            required = false,
            defaultValue = "maxmindGeolocationService"
        ) geolocationProvider: String?
    ): MutableMap<String?, Any?>? {
        return dataExporter.getCachesByIp(ip, geolocationProvider)
    }
}