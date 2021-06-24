package com.comcast.cdn.traffic_control.traffic_router.core.secure

import com.comcast.cdn.traffic_control.traffic_router.core.config.CertificateChecker
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesPublisher
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import java.lang.management.ManagementFactory
import java.util.concurrent.BlockingQueue
import java.util.concurrent.TimeUnit
import java.util.function.Consumer
import javax.management.Attribute
import javax.management.ObjectName

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */   class CertificatesPublisher(
    certificatesQueue: BlockingQueue<MutableList<CertificateData?>?>?, publishStatusQueue: BlockingQueue<Boolean?>?,
    certificateChecker: CertificateChecker?, trafficRouterManager: TrafficRouterManager?
) {
    private var deliveryServicesJson: JsonNode? = null
    private var deliveryServices: MutableList<DeliveryService?>? = ArrayList()
    private var running = true
    val worker: Thread?
    private fun publishCertificateList(certificateDataList: MutableList<CertificateData?>?) {
        try {
            val objectName = ObjectName(DeliveryServiceCertificatesMBean.Companion.OBJECT_NAME)
            ManagementFactory.getPlatformMBeanServer().setAttribute(
                objectName,
                Attribute("CertificateDataListString", ObjectMapper().writeValueAsString(certificateDataList))
            )
        } catch (e: Exception) {
            CertificatesPublisher.Companion.LOGGER.error(
                "Failed to add certificate data list as management MBean! " + e.javaClass.simpleName + ": " + e.message,
                e
            )
        }
    }

    fun getDeliveryServicesJson(): JsonNode? {
        return deliveryServicesJson
    }

    fun setDeliveryServicesJson(deliveryServicesJson: JsonNode?) {
        this.deliveryServicesJson = deliveryServicesJson
    }

    fun getDeliveryServices(): MutableList<DeliveryService?>? {
        return deliveryServices
    }

    fun setDeliveryServices(deliveryServices: MutableList<DeliveryService?>?) {
        this.deliveryServices = deliveryServices
    }

    fun destroy() {
        CertificatesPublisher.Companion.LOGGER.warn("Detected destroy setting running to false")
        running = false
        worker.interrupt()
    }

    companion object {
        private val LOGGER = Logger.getLogger(CertificatesPublisher::class.java)
    }

    init {
        worker = Thread(label@ Runnable {
            while (running) {
                try {
                    val certificateDataList = certificatesQueue.take() ?: continue
                    if (certificateChecker.certificatesAreValid(certificateDataList, deliveryServicesJson)) {
                        deliveryServices.forEach(Consumer { ds: DeliveryService? ->
                            val hasX509Cert = certificateChecker.hasCertificate(certificateDataList, ds.getId())
                            ds.setHasX509Cert(hasX509Cert)
                        })
                        publishCertificateList(certificateDataList)
                        publishStatusQueue.poll(2, TimeUnit.SECONDS)
                        trafficRouterManager.trackEvent("lastHttpsCertificatesUpdate")
                    } else {
                        trafficRouterManager.trackEvent("lastInvalidHttpsCertificates")
                    }
                } catch (e: Throwable) {
                    if (!running) {
                        return@label
                    }
                    CertificatesPublisher.Companion.LOGGER.warn(
                        "Interrupted while waiting for new certificate data list, trying again...",
                        e
                    )
                }
            }
        })
        worker.start()
    }
}