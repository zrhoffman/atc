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

import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServerMain
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.Protocol
import org.apache.log4j.Logger
import org.springframework.context.support.ClassPathXmlApplicationContext
import java.util.concurrent.ExecutorService

class NameServerMain {
    private var protocolService: ExecutorService? = null
    private var protocols: MutableList<Protocol?>? = null

    /**
     * Shuts down all configured protocols.
     */
    fun destroy() {
        for (protocol in getProtocols()) {
            protocol.shutdown()
        }
        getProtocolService().shutdownNow()
    }

    /**
     * Gets protocols.
     *
     * @return the protocols
     */
    fun getProtocols(): MutableList<Protocol?>? {
        return protocols
    }

    /**
     * Gets protocolService.
     *
     * @return the protocolService
     */
    fun getProtocolService(): ExecutorService? {
        return protocolService
    }

    /**
     * Initializes the configured protocols.
     */
    fun init() {
        for (protocol in getProtocols()) {
            getProtocolService().submit(protocol)
        }
    }

    /**
     * Sets protocols.
     *
     * @param protocols
     * the protocols to set
     */
    fun setProtocols(protocols: MutableList<Protocol?>?) {
        this.protocols = protocols
    }

    /**
     * Sets protocolService.
     *
     * @param protocolService
     * the protocolService to set
     */
    fun setProtocolService(protocolService: ExecutorService?) {
        this.protocolService = protocolService
    }

    companion object {
        private val LOGGER = Logger.getLogger(NameServerMain::class.java)

        /**
         * @param args
         */
        @JvmStatic
        fun main(args: Array<String>) {
            try {
                val ctx = ClassPathXmlApplicationContext("/dns-traffic-router.xml")
                ctx.getBean("NameServerMain")
                NameServerMain.Companion.LOGGER.info("PROCESS_SUCCEEDED")
            } catch (e: Exception) {
                NameServerMain.Companion.LOGGER.fatal("PROCESS_FAILED")
                NameServerMain.Companion.LOGGER.fatal(e.message, e)
                System.exit(1)
            }
        }
    }
}