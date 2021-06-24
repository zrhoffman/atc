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

import com.comcast.cdn.traffic_control.traffic_router.protocol.LanguidProtocol
import org.apache.coyote.http11.Http11NioProtocol
import org.apache.log4j.Logger

class LanguidProtocol : Http11NioProtocol(), RouterProtocolHandler {
    private var ready = false
    private var initialized = false
    private var mbeanPath: String? = null
    private var readyAttribute: String? = null
    private var portAttribute: String? = null

    @Throws(Exception::class)
    override fun init() {
        if (!isReady) {
            LanguidProtocol.Companion.log.info("Init called; creating thread to monitor the state of Traffic Router")
            LanguidPoller(this).start()
        } else {
            LanguidProtocol.Companion.log.info("Traffic Router is ready; calling super.init()")
            super.init()
            isInitialized = true
        }
    }

    @Throws(Exception::class)
    override fun start() {
        LanguidProtocol.Companion.log.info("Start called; waiting for initialization to occur")
        while (!isInitialized) {
            Thread.sleep(100)
        }
        LanguidProtocol.Companion.log.info("Initialization complete; calling super.start()")
        super.start()
    }

    override fun isReady(): Boolean {
        return ready
    }

    override fun setReady(isReady: Boolean) {
        ready = isReady
    }

    override fun isInitialized(): Boolean {
        return initialized
    }

    override fun setInitialized(isInitialized: Boolean) {
        initialized = isInitialized
    }

    override fun getMbeanPath(): String? {
        return mbeanPath
    }

    override fun setMbeanPath(mbeanPath: String?) {
        this.mbeanPath = mbeanPath
    }

    override fun getReadyAttribute(): String? {
        return readyAttribute
    }

    override fun setReadyAttribute(readyAttribute: String?) {
        this.readyAttribute = readyAttribute
    }

    override fun getPortAttribute(): String? {
        return portAttribute
    }

    override fun setPortAttribute(portAttribute: String?) {
        this.portAttribute = portAttribute
    }

    companion object {
        private val log = Logger.getLogger(LanguidProtocol::class.java)
    }
}