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
package com.comcast.cdn.traffic_control.traffic_router.core.ds

import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringRegistry
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import java.io.IOException

class SteeringRegistry {
    private var registry: MutableMap<String?, Steering?>? = HashMap()
    private val objectMapper: ObjectMapper? = ObjectMapper(JsonFactory())
    fun update(json: String?) {
        val m: MutableMap<String?, MutableList<Steering?>?>?
        m = try {
            objectMapper.readValue(json, object : TypeReference<HashMap<String?, MutableList<Steering?>?>?>() {})
        } catch (e: IOException) {
            LOGGER.error("Failed consuming Json data to populate steering registry, keeping current data:" + e.message)
            return
        }
        val steerings = m.values.iterator().next()
        val newSteerings: MutableMap<String?, Steering?> = HashMap()
        for (steering in steerings) {
            for (steeringTarget in steering.getTargets()) {
                steeringTarget.generateHashes()
            }
            newSteerings[steering.getDeliveryService()] = steering
        }
        newSteerings.forEach { (k: String?, newSteering: Steering?) ->
            val old = registry.get(k)
            if (old == null || old != newSteering) {
                for (target in newSteering.getTargets()) {
                    if (target.geolocation != null && target.geoOrder != 0) {
                        LOGGER.info("Steering " + newSteering.getDeliveryService() + " target " + target.deliveryService + " now has geolocation [" + target.latitude + ", " + target.longitude + "] and geoOrder " + target.geoOrder)
                    } else if (target.geolocation != null && target.weight > 0) {
                        LOGGER.info("Steering " + newSteering.getDeliveryService() + " target " + target.deliveryService + " now has geolocation [" + target.latitude + ", " + target.longitude + "] and weight " + target.weight)
                    } else if (target.geolocation != null) {
                        LOGGER.info("Steering " + newSteering.getDeliveryService() + " target " + target.deliveryService + " now has geolocation [" + target.latitude + ", " + target.longitude + "]")
                    } else if (target.weight > 0) {
                        LOGGER.info("Steering " + newSteering.getDeliveryService() + " target " + target.deliveryService + " now has weight " + target.weight)
                    } else if (target.order != 0) { // this target has a specific order set
                        LOGGER.info("Steering " + newSteering.getDeliveryService() + " target " + target.deliveryService + " now has order " + target.order)
                    } else {
                        LOGGER.info("Steering " + newSteering.getDeliveryService() + " target " + target.deliveryService + " now has weight " + target.weight + " and order " + target.order)
                    }
                }
            }
        }
        registry = newSteerings
        LOGGER.info("Finished updating steering registry")
    }

    fun verify(json: String?): Boolean {
        try {
            val mapper = ObjectMapper(JsonFactory())
            mapper.readValue(json, object : TypeReference<HashMap<String?, MutableList<Steering?>?>?>() {})
        } catch (e: IOException) {
            LOGGER.error("Failed consuming Json data to populate steering registry while verifying:" + e.message)
            return false
        }
        return true
    }

    fun has(steeringId: String?): Boolean {
        return registry.containsKey(steeringId)
    }

    operator fun get(steeringId: String?): Steering? {
        return registry.get(steeringId)
    }

    fun getAll(): MutableCollection<Steering?>? {
        return registry.values
    }

    companion object {
        private val LOGGER = Logger.getLogger(SteeringRegistry::class.java)
    }
}