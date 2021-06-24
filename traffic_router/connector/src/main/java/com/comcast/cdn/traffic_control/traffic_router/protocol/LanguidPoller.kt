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
package com.comcast.cdn.traffic_control.traffic_router.protocol

import com.comcast.cdn.traffic_control.traffic_router.protocol.LanguidPoller
import org.apache.log4j.Logger
import java.lang.Boolean
import java.lang.management.ManagementFactory
import javax.management.ObjectName
import kotlin.Exception

class LanguidPoller(private val protocolHandler: RouterProtocolHandler?) : Thread() {
    override fun run() {
        LanguidPoller.Companion.log.info("Waiting for state from mbean path " + protocolHandler.getMbeanPath())
        var firstTime = true
        while (true) {
            try {
                val mbs = ManagementFactory.getPlatformMBeanServer()
                // See src/main/opt/conf/server.xml
                // This is calling traffic-router:name=languidState
                val languidState = ObjectName(protocolHandler.getMbeanPath())
                val readyValue = mbs.getAttribute(languidState, protocolHandler.getReadyAttribute())
                val portValue = mbs.getAttribute(languidState, protocolHandler.getPortAttribute())
                val ready = Boolean.parseBoolean(readyValue.toString())
                val port = portValue.toString().toInt()
                if (firstTime) {
                    LanguidPoller.Companion.log.info("Waiting for ready state from Traffic Router before accepting connections on port $port")
                }
                if (ready) {
                    if (port > 0) {
                        protocolHandler.setPort(port)
                    }
                    LanguidPoller.Companion.log.info("Traffic Router published the ready state; calling init() on our reference to Connector with a listen port of " + protocolHandler.getPort())
                    protocolHandler.setReady(true)
                    protocolHandler.init()
                    break
                }
            } catch (ex: Exception) {
                // the above will throw an exception if the mbean has yet to be published
                LanguidPoller.Companion.log.debug(ex)
            }
            try {
                sleep(100)
            } catch (ex: InterruptedException) {
                LanguidPoller.Companion.log.fatal(ex)
            }
            firstTime = false
        }
    }

    companion object {
        private val log = Logger.getLogger(LanguidPoller::class.java)
    }
}