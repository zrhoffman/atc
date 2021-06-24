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

import org.apache.coyote.ProtocolHandler

interface RouterProtocolHandler : ProtocolHandler {
    open fun isReady(): Boolean
    open fun setReady(isReady: Boolean)
    open fun isInitialized(): Boolean
    open fun setInitialized(isInitialized: Boolean)
    open fun getMbeanPath(): String?
    open fun setMbeanPath(mbeanPath: String?)
    open fun getReadyAttribute(): String?
    open fun setReadyAttribute(readyAttribute: String?)
    open fun getPortAttribute(): String?
    open fun setPortAttribute(portAttribute: String?)
    open fun getPort(): Int
    open fun setPort(port: Int)
}