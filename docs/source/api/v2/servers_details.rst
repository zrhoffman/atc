..
..
.. Licensed under the Apache License, Version 2.0 (the "License");
.. you may not use this file except in compliance with the License.
.. You may obtain a copy of the License at
..
..     http://www.apache.org/licenses/LICENSE-2.0
..
.. Unless required by applicable law or agreed to in writing, software
.. distributed under the License is distributed on an "AS IS" BASIS,
.. WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
.. See the License for the specific language governing permissions and
.. limitations under the License.
..

.. _to-api-servers-details:

*******************
``servers/details``
*******************
Retrieves details of :ref:`tp-configure-servers`.


``GET``
=======
:Auth. Required: Yes
:Roles Required: "read-only"
:Response Type:  Array

Request Structure
-----------------
.. table:: Request Query Parameters

	+----------------+----------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
	| Name           | Required                               | Description                                                                                                                                                    |
	+================+========================================+================================================================================================================================================================+
	| hostName       | Required if no physLocationID provided | Return only the servers with this (short) hostname. Capitalization of "hostName" is important.                                                                 |
	+----------------+----------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
	| physLocationID | Required if no hostName provided       | Return only servers with this integral, unique identifier for the physical location where the server resides. Capitalization of "physLocationID" is important. |
	+----------------+----------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. code-block:: http
	:caption: Request Example

	GET /api/2.0/servers/details?hostName=edge HTTP/1.1
	User-Agent: python-requests/2.22.0
	Accept-Encoding: gzip, deflate
	Accept: */*
	Connection: keep-alive
	Cookie: mojolicious=...

Response Structure
------------------

.. code-block:: http
	:caption: Response Example

	HTTP/1.1 200 OK
	Access-Control-Allow-Credentials: true
	Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Set-Cookie, Cookie
	Access-Control-Allow-Methods: POST,GET,OPTIONS,PUT,DELETE
	Access-Control-Allow-Origin: *
	Content-Encoding: gzip
	Content-Type: application/json
	Set-Cookie: mojolicious=...; Path=/; Expires=Mon, 24 Feb 2020 01:27:36 GMT; Max-Age=3600; HttpOnly
	Whole-Content-Sha512: HW2F3CEpohNAvNlEDhUfXmtwpEka4dwUWFVUSSjW98aXiv10vI6ysRIcC2P9huabCz5fdHqY3tp0LR4ekwEHqw==
	X-Server-Name: traffic_ops_golang/
	Date: Mon, 24 Feb 2020 00:27:36 GMT
	Content-Length: 493

	{
		"limit": 1000,
		"orderby": "hostName",
		"response": [
			{
				"cachegroup": "CDN_in_a_Box_Edge",
				"cdnName": "CDN-in-a-Box",
				"deliveryservices": [
					1
				],
				"domainName": "infra.ciab.test",
				"guid": null,
				"hardwareInfo": null,
				"hostName": "edge",
				"httpsPort": 443,
				"id": 5,
				"iloIpAddress": "",
				"iloIpGateway": "",
				"iloIpNetmask": "",
				"iloPassword": "",
				"iloUsername": "",
				"interfaceMtu": 1500,
				"interfaceName": "eth0",
				"ip6Address": "fc01:9400:1000:8::3",
				"ip6Gateway": "fc01:9400:1000:8::1",
				"ipAddress": "172.16.239.3",
				"ipGateway": "172.16.239.1",
				"ipNetmask": "255.255.255.0",
				"mgmtIpAddress": "",
				"mgmtIpGateway": "",
				"mgmtIpNetmask": "",
				"offlineReason": "",
				"physLocation": "Apachecon North America 2018",
				"profile": "ATS_EDGE_TIER_CACHE",
				"profileDesc": "Edge Cache - Apache Traffic Server",
				"rack": "",
				"routerHostName": "",
				"routerPortName": "",
				"status": "REPORTED",
				"tcpPort": 80,
				"type": "EDGE",
				"xmppId": "edge",
				"xmppPasswd": ""
			}
		],
		"size": 1
	}
