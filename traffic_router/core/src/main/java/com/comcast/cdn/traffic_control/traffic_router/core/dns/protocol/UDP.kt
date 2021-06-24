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
package com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol

import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP
import org.apache.log4j.Logger
import org.xbill.DNS.Message
import org.xbill.DNS.WireParseException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket

class UDP : AbstractProtocol() {
    private var datagramSocket: DatagramSocket? = null

    /**
     * Gets datagramSocket.
     *
     * @return the datagramSocket
     */
    fun getDatagramSocket(): DatagramSocket? {
        return datagramSocket
    }

    override fun run() {
        while (!isShutdownRequested) {
            try {
                val buffer = ByteArray(UDP.Companion.UDP_MSG_LENGTH)
                val packet = DatagramPacket(buffer, buffer.size)
                datagramSocket.receive(packet)
                submit(UDPPacketHandler(packet))
            } catch (e: IOException) {
                UDP.Companion.LOGGER.warn("error: $e")
            }
        }
    }

    override fun shutdown() {
        super.shutdown()
        datagramSocket.close()
    }

    /**
     * Sets datagramSocket.
     *
     * @param datagramSocket
     * the datagramSocket to set
     */
    fun setDatagramSocket(datagramSocket: DatagramSocket?) {
        this.datagramSocket = datagramSocket
    }

    public override fun getMaxResponseLength(request: Message?): Int {
        var result: Int = UDP.Companion.UDP_MSG_LENGTH
        if (request != null && request.opt != null) {
            val opt = request.opt
            result = opt.payloadSize
        }
        return result
    }

    /**
     * This class is package private for unit testing purposes.
     */
    internal inner class UDPPacketHandler
    /**
     * This method is package private for unit testing purposes.
     *
     * @param packet
     */(private val packet: DatagramPacket?) : SocketHandler {
        private var cancel = false
        override fun run() {
            if (cancel) {
                cleanup()
                return
            }
            try {
                val client = packet.getAddress()
                val request = ByteArray(packet.getLength())
                System.arraycopy(packet.getData(), 0, request, 0, request.size)
                val response = query(client, request)
                val outPacket = DatagramPacket(
                    response, response.size,
                    packet.getSocketAddress()
                )
                getDatagramSocket().send(outPacket)
            } catch (e: WireParseException) {
                // This is already recorded in the access log
            } catch (e: Exception) {
                UDP.Companion.LOGGER.error(e.message, e)
            }
        }

        override fun cleanup() {
            // noop for UDP
        }

        override fun cancel() {
            cancel = true
        }
    }

    companion object {
        private val LOGGER = Logger.getLogger(UDP::class.java)
        private const val UDP_MSG_LENGTH = 512
    }
}