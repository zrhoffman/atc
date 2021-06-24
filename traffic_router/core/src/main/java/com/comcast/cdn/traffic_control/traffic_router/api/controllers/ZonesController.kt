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
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseBody

@Controller
@RequestMapping("/stats/zones")
class ZonesController {
    @Autowired
    var dataExporter: DataExporter? = null

    @RequestMapping(value = ["/caches"])
    @ResponseBody
    fun getAllCachesStats(): MutableMap<String?, Any?>? {
        val statsMap: MutableMap<String?, Any?> = HashMap()
        statsMap["dynamicZoneCaches"] = dataExporter.getDynamicZoneCacheStats()
        statsMap["staticZoneCaches"] = dataExporter.getStaticZoneCacheStats()
        return statsMap
    }

    @RequestMapping(value = ["/caches/{filter:static|dynamic}"])
    @ResponseBody
    fun getCachesStats(@PathVariable("filter") filter: String?): MutableMap<String?, Any?>? {
        return if ("static" == filter) dataExporter.getStaticZoneCacheStats() else dataExporter.getDynamicZoneCacheStats()
    }
}