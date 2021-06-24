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

import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody
import java.net.URL
import java.net.URLDecoder
import javax.servlet.http.HttpServletRequest

@Controller
@RequestMapping("/deliveryservices")
class DeliveryServicesController {
    @Autowired
    var trafficRouterManager: TrafficRouterManager? = null

    @RequestMapping
    @ResponseBody
    fun getDeliveryService(
        request: HttpServletRequest?,
        @RequestParam(name = "url") url: String?
    ): ResponseEntity<MutableMap<String?, String?>?>? {
        val decodedUrl: URL
        decodedUrl = try {
            URL(URLDecoder.decode(url, "UTF-8"))
        } catch (e: Exception) {
            return ResponseEntity.badRequest().body(null)
        }
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        val deliveryService = trafficRouter.cacheRegister.getDeliveryService(HTTPRequest(request, decodedUrl))
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null)
        val map: MutableMap<String?, String?> = HashMap()
        map["id"] = deliveryService.id
        return ResponseEntity.ok(map)
    }
}