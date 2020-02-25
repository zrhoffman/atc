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

.. _to-api-deliveryservice_requests-id-assign:

******************************************
``deliveryservice_requests/{{ID}}/assign``
******************************************
Assign a :term:`Delivery Service Request` to a user.

``PUT``
=======
:Auth. Required: Yes
:Roles Required: "admin" or "operations"
:Response Type:  Object

Request Structure
-----------------

.. code-block:: http
	:caption: Request Example

	PUT /api/2.0/deliveryservice_requests/1/assign HTTP/1.1
	User-Agent: python-requests/2.22.0
	Accept-Encoding: gzip, deflate
	Accept: */*
	Connection: keep-alive
	Cookie: mojolicious=...
	Content-Length: 28

	{
		"id": 1,
		"assigneeId": 2
	}

Response Structure
------------------
:author:            The author of the Delivery Service Request
:authorId:          The integral, unique identifier assigned to the author
:changeType:        The change type of the :term:`DSR <Delivery Service Request>`. It can be ``create``, ``update``, or ``delete``....
:createdAt:         The date and time at which the :term:`DSR <Delivery Service Request>` was created, in ISO format.
:deliveryService:   The delivery service that the :term:`DSR <Delivery Service Request>` is requesting to update.
:id:                The integral, unique identifier assigned to the :term:`DSR <Delivery Service Request>`
:lastEditedBy:      The username of user who last edited this :term:`DSR <Delivery Service Request>`
:lastEditedById:    The integral, unique identifier assigned to the user who last edited this :term:`DSR <Delivery Service Request>`
:lastUpdated:       The date and time at which the :term:`DSR <Delivery Service Request>` was last updated, in ISO format.

.. code-block:: http
	:caption: Response Example

	HTTP/1.1 200 OK
	Access-Control-Allow-Credentials: true
	Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Set-Cookie, Cookie
	Access-Control-Allow-Methods: POST,GET,OPTIONS,PUT,DELETE
	Access-Control-Allow-Origin: *
	Content-Encoding: gzip
	Content-Type: application/json
	Set-Cookie: mojolicious=...; Path=/; Expires=Sun, 23 Feb 2020 14:45:51 GMT; Max-Age=3600; HttpOnly
	Whole-Content-Sha512: h7uBZHLQtRYbOSOR5AtQQrZ4uMeEWivWNT74fCf6WtLbAMwGpRrMjNmBYKduv48DEnRqG6WVM/4nBu3AkCUqPw==
	X-Server-Name: traffic_ops_golang/
	Date: Sun, 23 Feb 2020 13:45:51 GMT
	Content-Length: 931

	{
		"alerts": [
			{
				"text": "deliveryservice_request was updated.",
				"level": "success"
			}
		],
		"response": {
			"assigneeId": 2,
			"assignee": "admin",
			"authorId": 2,
			"author": "admin",
			"changeType": "update",
			"createdAt": "2020-02-23 11:06:00+00",
			"id": 1,
			"lastEditedBy": "admin",
			"lastEditedById": 2,
			"lastUpdated": "2020-02-23 13:45:51+00",
			"deliveryService": {
				"active": true,
				"anonymousBlockingEnabled": false,
				"cacheurl": null,
				"ccrDnsTtl": null,
				"cdnId": 2,
				"cdnName": "CDN-in-a-Box",
				"checkPath": null,
				"displayName": "Demo 2",
				"dnsBypassCname": null,
				"dnsBypassIp": null,
				"dnsBypassIp6": null,
				"dnsBypassTtl": null,
				"dscp": 0,
				"edgeHeaderRewrite": null,
				"geoLimit": 0,
				"geoLimitCountries": null,
				"geoLimitRedirectURL": null,
				"geoProvider": 0,
				"globalMaxMbps": null,
				"globalMaxTps": null,
				"httpBypassFqdn": null,
				"id": 1,
				"infoUrl": null,
				"initialDispersion": 1,
				"ipv6RoutingEnabled": true,
				"lastUpdated": "0001-01-01 00:00:00+00",
				"logsEnabled": true,
				"longDesc": "Apachecon North America 2018",
				"longDesc1": null,
				"longDesc2": null,
				"matchList": [
					{
						"type": "HOST_REGEXP",
						"setNumber": 0,
						"pattern": ".*\\.demo1\\..*"
					}
				],
				"maxDnsAnswers": null,
				"midHeaderRewrite": null,
				"missLat": 42,
				"missLong": -88,
				"multiSiteOrigin": false,
				"originShield": null,
				"orgServerFqdn": "http://origin.infra.ciab.test",
				"profileDescription": null,
				"profileId": null,
				"profileName": null,
				"protocol": 2,
				"qstringIgnore": 0,
				"rangeRequestHandling": 0,
				"regexRemap": null,
				"regionalGeoBlocking": false,
				"remapText": null,
				"routingName": "video",
				"signed": false,
				"sslKeyVersion": null,
				"tenantId": 1,
				"type": "HTTP",
				"typeId": 1,
				"xmlId": "demo1",
				"exampleURLs": [
					"http://video.demo1.mycdn.ciab.test",
					"https://video.demo1.mycdn.ciab.test"
				],
				"deepCachingType": "NEVER",
				"fqPacingRate": null,
				"signingAlgorithm": null,
				"tenant": "root",
				"trResponseHeaders": null,
				"trRequestHeaders": null,
				"consistentHashRegex": null,
				"consistentHashQueryParams": [
					"abc",
					"pdq",
					"xxx",
					"zyx"
				],
				"maxOriginConnections": 0,
				"ecsEnabled": false
			},
			"status": "submitted"
		}
	}
