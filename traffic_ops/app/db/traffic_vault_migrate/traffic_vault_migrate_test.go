package main

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
 */

import (
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/lestrrat/go-jwx/jwk"

	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/lib/go-util"
)

func testBackend(t *testing.T, backend TVBackend) {
	sslkey := SSLKey{
		DeliveryServiceSSLKeys: tc.DeliveryServiceSSLKeys{
			CDN:             "CDN-in-a-Box",
			DeliveryService: "demo1",
			Hostname:        "*.demo1.mycdn.ciab.test",
			Key:             "demo1",
			Version:         1,
			Certificate: tc.DeliveryServiceSSLKeysCertificate{
				Crt: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUhBRENDQk9pZ0F3SUJBZ0lGRmhGWklab3dEUVlKS29aSWh2Y05BUUVMQlFBd2dhOHhDekFKQmdOVkJBWVQKQWxWVE1SRXdEd1lEVlFRSUV3aERiMnh2Y21Ga2J6RVBNQTBHQTFVRUJ4TUdSR1Z1ZG1WeU1SVXdFd1lEVlFRSwpFd3hEUkU0dGFXNHRZUzFDYjNneEZUQVRCZ05WQkFzVERFTkVUaTFwYmkxaExVSnZlREVsTUNNR0ExVUVBeE1jClEwUk9MV2x1TFdFdFFtOTRJRWx1ZEdWeWJXVmthV0YwWlNCRFFURW5NQ1VHQ1NxR1NJYjNEUUVKQVJZWWJtOHQKY21Wd2JIbEFhVzVtY21FdVkybGhZaTUwWlhOME1CNFhEVEl4TURFeU5URTJNekF3TWxvWERUSXlNREV5TlRFMgpNekF3TWxvd2FqRUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0VOdmJHOXlZV1J2TVE4d0RRWURWUVFICkRBWkVaVzUyWlhJeEZUQVRCZ05WQkFvTURFTkVUaTFwYmkxaExVSnZlREVnTUI0R0ExVUVBd3dYS2k1a1pXMXYKTVM1dGVXTmtiaTVqYVdGaUxuUmxjM1F3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQwpBUUN0SitqcWpFMXlVdmJZa0RaV2t4RUY2WWhVelcrdmM0TzFHRmgrS2pQalJySlFWNnQ3ckVkaERTZGJZeG4xCnIxZTErQVlDWXdKWm1KU2lUTU4yY000anJOdUd5TUsybVpqUkErVlIrd1JBeUJjR0VUeG91cEFhcitvTHo3TUgKNjlOMVZ6c1piakxWY1Y2Q1h4ODFyMkV6emd5UkJjQVlTdElxY29rbnc3eXNYdXRNaDNDSSs2OXNGZXBQeUZobgpUWjIwVzRYWmxUYnJ2eWE4bUkvb0R3T0ZVaVhJM0dtRTN1TGdEY3F5SVQySThHSzFnK29xcnA0Si93RDhCaGNSCldVTnRudGVsMDdHdXVSZGRySWl0SGRjVVdmUWFSakJnQ0wvR2Z2SnVYTENRQm1sa2hOQXk3VnkwNXB0Y2RTclQKSkxHQXB2NEh2a0hEUUtaaklRcFlFWHd3d3RLREZkQ0Y3Y1RtZzRZZWN2ZDhPeEpOR2ZsR2hKTjVPekl2a1RNUgpPUTN6RXFzK2tjeDNhRC9aWnRyL05BWnU0TWxmZGVaeCtNM21vaFh4eXNqZFZBUGwzemFPYlBsekdRYlVHVW5XCmFScG0vWm1CUHFlMHFlSnZDUXExdFpxd2FCVThGOFFBNFZLckgycWsxam1tcTVIY1FET2ZUYlRvdlQ5K3hDMngKck5lM0FObERsckdHeWJTWmUvOVNvSysrMlliRGNUYkRXUmp4TGRpNGdDelBRUHdmTm5pbEJidlV6amVPM0RFOAo0emIzK0dHbFV6MlFTamJhK1kzSllaTXZHRFdrWXBadUxNV1JtWWREY3NJQTBuN1h6TDAwSHRtckllMVBBcEJqCmEra0JrYVNNK3FTOS9pZEcwL3J0VjRrSE5MeCt0Y0ZCY0N6NUNQYnA0eVd4N1FJREFRQUJvNElCWlRDQ0FXRXcKQ1FZRFZSMFRCQUl3QURBUkJnbGdoa2dCaHZoQ0FRRUVCQU1DQmtBd0hRWURWUjBPQkJZRUZCTUJTbTVKSkpELwpwQkltbFpqUmFyaWNSNXROTUlIWUJnTlZIU01FZ2RBd2djMkFGQk9zYlZINFhHUFIyM296NkJxM3JJUDNnZ1VFCm9ZR3RwSUdxTUlHbk1Rc3dDUVlEVlFRR0V3SlZVekVSTUE4R0ExVUVDQk1JUTI5c2IzSmhaRzh4RHpBTkJnTlYKQkFjVEJrUmxiblpsY2pFVk1CTUdBMVVFQ2hNTVEwUk9MV2x1TFdFdFFtOTRNUlV3RXdZRFZRUUxFd3hEUkU0dAphVzR0WVMxQ2IzZ3hIVEFiQmdOVkJBTVRGRU5FVGkxcGJpMWhMVUp2ZUNCU2IyOTBJRU5CTVNjd0pRWUpLb1pJCmh2Y05BUWtCRmhodWJ5MXlaWEJzZVVCcGJtWnlZUzVqYVdGaUxuUmxjM1NDQlJZUldTR1pNQTRHQTFVZER3RUIKL3dRRUF3SUZvREFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQVRBaUJnTlZIUkVFR3pBWmdoY3FMbVJsYlc4eApMbTE1WTJSdUxtTnBZV0l1ZEdWemREQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FnRUFPWGlubk44bTVnRkV4TFJSCkVtZnRoVk5JUGpQTUQ4ejlHc3YwN1hDU1orZnVxSEZySnMzV0xXL29rb1dyUjhHRkZGZXZmWGlSeDNUUFB5b2oKVWNQUjgrbWluS2I1U2w2Z2xJME1qdTkvSWVCTGhMcXF5a2JIUU1FLzFMdTFieGNkNG5FT2tvN045US95Sy9XTAoyU1kzZkRYQS9LRDFCckFTM09BNE9GUWovbWlJbjU5YTllSDFkbTdQY0taQTdIUGlvMVlpTlYvcHNSVHVvT3lFCmhMd3BxK2tKOE5wUDVZaFhpSUJRNzM4czhrWGNSQjZ1YkJqcWJsdlRxKytkVEFpWnVBTHJJMGdMWlhyYWZzVkwKc25MaTg1N0NMUlVvaTVMTzZrK0pRVGYrQnJ2UDBpNDB2enV0VFJWczJEUjQvWlRRMTJPRGM1Yk5EbVhiQVU1NwpBekZPS0kydGgxVEdKQ0hheTkrUXJBOCtQbWpidVh4ZVRHaHB4c2Y4ZDYxTk9mRlc0YXY0eGFkY25qTjVLYUN2Ci9QaEFoQUd2bW1RbzhLSFBzVzA3MUpUQkdOQ05aOGR2RlJRNnlvdEE0WHVKSmRIK2M0ZEF1bkpUUDQ1MUNGYkoKQWgzNzVYbmRpcjUvNkJUanNMRC90TVNYRFNKSzZwNFg0MHVjSXRwb2UyUGRBekJqenNVamhWMWxBeVF0RGtIUwo5dnM5eTk2QXV6RnYxanhHSHZCajBham1JT1JDamp2KzJNTUhPWVJPcENMUGVOVlhjQ3ZCSUFQT3JScm1vTVVjCm82bENqTHlvSzJhR1MveStLOFpyTmM5c3dsQXFkNS83TnhhMU5zT2RUM0FYMkVZOHhQZHNwaFVJOGU3OC9aWDEKQWtaNkdWL1VDSEpYdlg3K1RmNWVEWDcwSFpnPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
				Key: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUpRd0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQ1Mwd2dna3BBZ0VBQW9JQ0FRQ3RKK2pxakUxeVV2YlkKa0RaV2t4RUY2WWhVelcrdmM0TzFHRmgrS2pQalJySlFWNnQ3ckVkaERTZGJZeG4xcjFlMStBWUNZd0pabUpTaQpUTU4yY000anJOdUd5TUsybVpqUkErVlIrd1JBeUJjR0VUeG91cEFhcitvTHo3TUg2OU4xVnpzWmJqTFZjVjZDClh4ODFyMkV6emd5UkJjQVlTdElxY29rbnc3eXNYdXRNaDNDSSs2OXNGZXBQeUZoblRaMjBXNFhabFRicnZ5YTgKbUkvb0R3T0ZVaVhJM0dtRTN1TGdEY3F5SVQySThHSzFnK29xcnA0Si93RDhCaGNSV1VOdG50ZWwwN0d1dVJkZApySWl0SGRjVVdmUWFSakJnQ0wvR2Z2SnVYTENRQm1sa2hOQXk3VnkwNXB0Y2RTclRKTEdBcHY0SHZrSERRS1pqCklRcFlFWHd3d3RLREZkQ0Y3Y1RtZzRZZWN2ZDhPeEpOR2ZsR2hKTjVPekl2a1RNUk9RM3pFcXMra2N4M2FEL1oKWnRyL05BWnU0TWxmZGVaeCtNM21vaFh4eXNqZFZBUGwzemFPYlBsekdRYlVHVW5XYVJwbS9abUJQcWUwcWVKdgpDUXExdFpxd2FCVThGOFFBNFZLckgycWsxam1tcTVIY1FET2ZUYlRvdlQ5K3hDMnhyTmUzQU5sRGxyR0d5YlNaCmUvOVNvSysrMlliRGNUYkRXUmp4TGRpNGdDelBRUHdmTm5pbEJidlV6amVPM0RFODR6YjMrR0dsVXoyUVNqYmEKK1kzSllaTXZHRFdrWXBadUxNV1JtWWREY3NJQTBuN1h6TDAwSHRtckllMVBBcEJqYStrQmthU00rcVM5L2lkRwowL3J0VjRrSE5MeCt0Y0ZCY0N6NUNQYnA0eVd4N1FJREFRQUJBb0lDQUYxVkhzR1dJSVNYM1gvN3M1NVVwUjlYCnNtbHJWbUR1MWJZK1NpeXZHTXJQcDN1UTFkalNrcUxvVVNkOE1sandTMG5GUjQvdnlDdDlCOWkzb2Ivc3ErQWsKNHlzeWVXbXRQdWFpdisvQmFwaDBnWngrbTk0amVWczVLT0YyOFp3NmEvOWFwbnRkbjc3VzNjZE4rR2VhZ2IxSAp1aFJOVWk2RjNlU05XZ3A2QWUrek5nZEpGY3B3Unl6dVh4N2o4V3ExTm1VcDArcms5L1o0VVN2azIrU01leXhZCmpBOUpad0w4bExPS0c1Q0tSRDNVdkkvMGE3clg1azJqQ3VmTmJJK29XcVR5c25BcXZDSmVtQTZnMmdiZUI3bHIKaHh6R2FuckpISDJrblk0SkhnNXp0a2s5SVcvaDYwK0M0WWtqaXBMR3UzcUtDSEVxQnc1MGdYcjdLelV2TDQzQgp4ZXJxaXVQWG9jWXExUHdWMnk3RGEycERobXl0Wlh5U05kLzU0aDBESk00R1lDRUlNZmhnNklpRnFEK3BDbjhmCllneHQwSlFCd24yT0FudW1RcEwvUkY2YjlQckhFQ3QvRmprU2tOVGNHUDVCU0ZZcVF3RkMwRTBtV1hpTFZ2U08KclEwZDVWWkwxTUx5R21yQzlQbTJvNHpsK3ZOaWg3a1NZNy9hUkx3OHNjY01jVDU1WTJWSVhnQ2hNSGpQYTc2cgpDbmhVMUZFRDFlODludzk1RUNvRmRxVTBqOEN5Y0ZMUWhGdkRVUSt1Skp6WHgxbXhNMmlJUzlxWWN6T3Y5VWRLCmZ4SGo5RHFKZ0lsNS8rREhycUFmNC9KOWFrREYwVkJPelQxVFNaZlQrRzJRNXYyb25PbjRQdGR3eUd5MWM2cG0KWUw4UG9TZ1RRMjIxSjZRZFNNbEJBb0lCQVFEYVl0L2tXVDZBaXFFN0VBakJKZkMvMENmRmdYRUNhTU1XRG9rVwpmNXNVV0pFRGJ2a0oxa0JHbVF3MTdPRndlbjRXUTdhdnFXWXdXeThteFJxUGNSaTlLME5TZTgvOWpvMHR6WVFFCk9EczRTbnhnYmUrR00wMW0wNzhnckZMcUttdjZBc3RTd1cyQlNYSmg3VTQvNXhsOTQ0MFcrRVNmOFMyM1lwQTEKMUNqcFRDRWdhR3lmK3I2RjdGeFdIVW5IdVNodzNDbzBwT0FhUXV6NjQyTlZrZmUyYU1BMWNaV3dTdlBSelBQcwp5Wk9KcTlQYVFVczNiRXJhd3F1b1grM3I2Ujd1L20zREZnUTR4M2Q2WnBtN0dDRHVmZnMzZHErdWRqZ1JSaDBvCnJuYjZFUEJhdGlTNjdzVFdLckhMMC9vbjkySUNmckRoZ1ZSMWV6UlNNWmJGbng1eEFvSUJBUURLK3JzeS9UeWoKclZOSmZ4bkJDdUxFWXZEVlN2c2RTWnNNL3cwNHZ0am5UbHZMKzNPWkRyTGpvOE1OSENPOWt2Q2p5U01yZUwyawp1emg1ZTJYR1Zxb2QvRWluMmNjRnlTbTJiS0NybmxVYzNwaW4zTXFLTkFLUzFBUUlocjdFZzVpRS9XZHIzSXlnCmdUMmVUM2M3Y0ptUzF2bTNGZWdISWpvYTk3RjRsVEFVVEdMa2ZWN1Byc0ZIeDh2OEhFemx4WnErZmRUS1MydEgKRTRHdkZ3SSsxWFpYRVFPOXUzak9HbXVmUXlobUdQSFk0ck1JWkNpZlNNL3pBMUJQZWtFS0lGNVVKTzBvL1ozWgp5MDdhcEJUZURpR0FUSGxZOEZsbjV0Q1dMcVc0TFdaemMzUVBwK0gzQ0tvYTE0dUlwRzJVeHhmSzZhbkxXVXl2CjhDTGdqQlFuYlFFOUFvSUJBUUM1amJFMlVDMnZBaHNrRitlWVZTaE5rZ3Q0NFJhb09XTW81b2pNT1BnSFBZbFoKSlgwc1FvS3llVy9La2M2cXh5bEN1WjRMZXg5OGpyMXRiNk8xcFI2ai9KSmpEeGdXRkgwWUlicTk2eGxHSnVPdQorem05Q1BJSElIc1F3OXBmWkZRQ1JVV0V0eHpYOFJQaTZNTEh3UkFEeXNnaWNDZSt6aWxOMjgwMEwyUGpkZS9mCm5WcE9RN3FHQitJY3VSM3JPUU9IZ1VuTEdSdmd0R1N1ZDIzN1V0N3FlZTUyZWwvNVBuWVVHTlJZcUoxWEtFd0UKOGQxNjVlUmtJMnUrMEdOVFF1d3BuTHllT2FLMHE2WjB0YUNCTzJzZnVLTXU2UVUwY3ZZSWwwNUhOcFdZdTdPOQpIMjN0OXRvQUxwNksxVDJEbjhvQzNLcGxzSUdXb0d4QU9pb2xGNkhCQW9JQkFGNWlIRzNuUnkwc3lVK2hwRTRaClM3elo3UGFoT1FjelZML0VVVmVUbHJSbndWT21odWdpNTVmbWJDcEtiV3dYU1lJL1l2VXgzYTBkeVhManFEMkQKeXZMS2Z0WmQ4NmVERkx4WTRwVXF1SlVHQktINWpzeVl4cUdUcUpSMlkzcHBYcUJvWEpEUkt5cnZMY0hSWGJYcgo4OTFOelN3UEthYzNpU0ZGRCtic0tFRW9DOHdIWi9EV1o5V0MyQjFRNDRqc1M3cE1OSWdrYmF2TkxENUlTcWtCCkJWZ1M5MVJnT2hwTU9zTUJyV1ZjTUFrVDBRQVQ0cmUrV2NPOFJMblFOVElLUHhLTllTSHdYRmdMcTQwTFF4REcKTFZuRk5aL2ZreE0zUnNLdXlpeE1JQm1MRStxN3U5enMwSHhPd2ZrMXpDYWtOVElMV1FMUGNWTldMRUdSb1VWNwo4RmtDZ2dFQkFNbTlqUUJWbk5TY0dPUm9zbm5pVGhnZGNrOExSVS9GVXAzazdSOFgyYmgzZklkUjlKZnpyQnVECnluOVF4bktNaWlraVhPM1lTTGlaUHU1eTN3a2d1RGJPeVR0ekxGakhHQkh1QU9Nc3VidGxCUkEyUEYvaXdVSTIKWGFrcVB3b0ZzdTR3MXZ2RUZaaXdMd0IzaUtCN1I3M0RzSi9Oei9ZbDN4V1VBMVRBU3Q3MCtmRCtpYU80U3BhcApodzNNK1F4NVNnYXZobGZxdzVuUTR6RkZ3UEhiaHFUWmlseXIvODZxOFNBVkNZSlFLdTdqOXRwR3JsUVZqUkJvCmRkVG5wQ05DN2R5QkhCV2QybVE5czNDcllacUZHNjNjWmZqWnJOQmhQSmliY2xYWjRROGNGQ2JCSFdMTE51VXIKQkpic1Y4d2x2aG1FMUF0dmRkZjEvRkxBbTR0ZEhqbz0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ==",
				CSR: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJRXJ6Q0NBcGNDQVFBd2FqRUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0VOdmJHOXlZV1J2TVE4dwpEUVlEVlFRSERBWkVaVzUyWlhJeEZUQVRCZ05WQkFvTURFTkVUaTFwYmkxaExVSnZlREVnTUI0R0ExVUVBd3dYCktpNWtaVzF2TVM1dGVXTmtiaTVqYVdGaUxuUmxjM1F3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QXcKZ2dJS0FvSUNBUUN0SitqcWpFMXlVdmJZa0RaV2t4RUY2WWhVelcrdmM0TzFHRmgrS2pQalJySlFWNnQ3ckVkaApEU2RiWXhuMXIxZTErQVlDWXdKWm1KU2lUTU4yY000anJOdUd5TUsybVpqUkErVlIrd1JBeUJjR0VUeG91cEFhCnIrb0x6N01INjlOMVZ6c1piakxWY1Y2Q1h4ODFyMkV6emd5UkJjQVlTdElxY29rbnc3eXNYdXRNaDNDSSs2OXMKRmVwUHlGaG5UWjIwVzRYWmxUYnJ2eWE4bUkvb0R3T0ZVaVhJM0dtRTN1TGdEY3F5SVQySThHSzFnK29xcnA0Sgovd0Q4QmhjUldVTnRudGVsMDdHdXVSZGRySWl0SGRjVVdmUWFSakJnQ0wvR2Z2SnVYTENRQm1sa2hOQXk3VnkwCjVwdGNkU3JUSkxHQXB2NEh2a0hEUUtaaklRcFlFWHd3d3RLREZkQ0Y3Y1RtZzRZZWN2ZDhPeEpOR2ZsR2hKTjUKT3pJdmtUTVJPUTN6RXFzK2tjeDNhRC9aWnRyL05BWnU0TWxmZGVaeCtNM21vaFh4eXNqZFZBUGwzemFPYlBsegpHUWJVR1VuV2FScG0vWm1CUHFlMHFlSnZDUXExdFpxd2FCVThGOFFBNFZLckgycWsxam1tcTVIY1FET2ZUYlRvCnZUOSt4QzJ4ck5lM0FObERsckdHeWJTWmUvOVNvSysrMlliRGNUYkRXUmp4TGRpNGdDelBRUHdmTm5pbEJidlUKemplTzNERTg0emIzK0dHbFV6MlFTamJhK1kzSllaTXZHRFdrWXBadUxNV1JtWWREY3NJQTBuN1h6TDAwSHRtcgpJZTFQQXBCamEra0JrYVNNK3FTOS9pZEcwL3J0VjRrSE5MeCt0Y0ZCY0N6NUNQYnA0eVd4N1FJREFRQUJvQUF3CkRRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFIUkJKU0F3VCtpY1d4SDdWTW1pWERWRFhUVzB0RGxROXI1Sm5zdjMKZ3kxdlJPQ3pOZzNHZk1xOVhqRUd0VG1udDlGRHpRckZCa1hEU25rWktESFJZdFZ1bXpSbFlGaTBUWUV4bUtMbQpOcTkxU0FEdmhubUlqUHZRT0dmZTFJWXNrK3M1YUYveXVjYy8ybjkrMWI0R1hPUFBxeDFmNlJTVm5oNnozb0VKCnRSMHNIWDF2bkR0Ni9VejByOEU0dzRtbVljeHRBY2RGR1UvWUZnU0l0NVRWOU1zdUtKRDFrVGIrUEM4ZUhEQlgKdFRPanZzaUJhWTRtaklHTUJ6Nk8wSHljYkJYbXR5N3VLYkVVcm91YVRnbFdLZ2dmQnRsUllxWjRRSXhjSDQrVQpscWlhdDREd0tybUJSaHNyRVJNSmk1L2hlemRhNEpVSnh0dUpDbHdpR3IvTzNBdUVma25jclNTSjlpaHZZWDdQCllLNzhZTjdEbU5PVDdqVzBITDMxTlFwRzZTWGhvcjRoeVVzNmZEWkM2em55cWVTcmU2NnhoOEQzV29MU2pwYUEKNEw4UGRibnVJTmh0bWNDZE5VaVJMUFU0ODJtVUdSb3p0dlIySGtyVXBNSkxWQXJQOEJzRVdQbnVyZ1NYZCsrTApQSGtyMEgzaVRhRTlRT1dBYy9zQVUvOEVaelcxUlFDR0E5KzVrc2lPcGw0Ynhuay82elkwei9FYUxUSGNOMWxTCjJnRW9md0E5TXl0ZzYyS1FlaUZ4dEpFWHdwU0NqMWthK25BUkFuVlBSUkhORWhvUjN3aXpyZUprbUlaQ0pzcC8KYVBZcWU1YXBDTkNpU081YVBqTTJvNndDTkJGTXdkSXhRVUpKT08ybDRTQm5mR2RFMUh1SHhZdEF3Z2JCVVBwQgp1VnZZCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=",
			},
		},
		Version: "1",
	}
	uri := URISignKey{
		DeliveryService: "defaultDS2",
		Keys: tc.JWKSMap{
			"defaultDS2": {
				RenewalKid: util.StrPtr("h"),
				Keys: []jwk.EssentialHeader{
					{
						Algorithm: "a",
						KeyID:     "h",
					},
				},
			},
		},
	}
	url := URLSigKey{
		DeliveryService: "url_sig_defaultDS2.config",
		URLSigKeys: map[string]string{
			"key0":  "dvfYTOnrUKFKygadPyKeAy9YAGDHeGit",
			"key1":  "bZkwxGd0_39QEfAmATMeCi1I4QVkRFmI",
			"key10": "xjgpBWzcmHs9jj4VHS18ubV_MBf139FR",
			"key11": "3OvSDnhlkE7OkmhvJln0WH5DJurn2n1W",
			"key12": "X1CKnSRWGZ_NHe7xKKt25yN0bb9RqCqk",
			"key13": "5Kpc5qO9DxdJGeJJPZh8tKzzCsJIDxZL",
			"key14": "RfohjQAZGFveIW_ayJEylVoL0kj6i7NM",
			"key15": "_M8alzW4Bb3U_usm02AtzhAJzJL9WCLb",
			"key2":  "l_kIIJQf888gyhq_kID0M3qHbuY94GP0",
			"key3":  "xICfZ683V83GFsp9yPGEIB1wCjBREbzI",
			"key4":  "NbkZedtNQHSBLOhkE68pfoD2idtAou7f",
			"key5":  "xwE0QwHcCc0AbhOBbg6gk7zTHNsSWe9L",
			"key6":  "N4n9mRT6bPDZztt3GUFE1i06WgufRKuZ",
			"key7":  "KWUhYWCdUyQQs0eNESSbHRfy91f_NxcO",
			"key8":  "DED7R79IFIm94ICz9fcar9CVsUvXWYES",
			"key9":  "d10AuREiu59hjQtwZM_l92bacI5VVBmK",
		},
	}
	dnssec := DNSSecKey{
		CDN: "dnssec-gen0",
		DNSSECKeysTrafficVault: map[string]tc.DNSSECKeySetV11{
			"defaultDS2": {
				ZSK: []tc.DNSSECKeyV11{
					{
						InceptionDateUnix:  1622818189,
						ExpirationDateUnix: 1628002189,
						Name:               "defaultds2.test1.host.",
						TTLSeconds:         60,
						Status:             "new",
						EffectiveDateUnix:  1622818189,
						Public:             "ZGVmYXVsdGRzMi50ZXN0MS5ob3N0Lgk2MAlJTglETlNLRVkJMjU2IDMgNSBBd0VBQWQxSGFvTm42QWdQT0g1b2ZRbGM3OHAwZW0rYzd0YzdrZStqdVEzWW54a0lUcWpuclBkNWJOcU9JODhWazhXdm5tdHNXN0JXNWxScW05SVl5c2l0SVdnb0NVaUU0VjJSbWk2S1hIUTIrb3lEeVBrU3dxLzV2Z3NrYTBwMDhNVEM3NVpsQ3dPMXV3Y2tMY21YSDYrblVJUXZxaDZTOFJ0NWZXRlFMVXFmbFFoTg==",
						Private:            "UHJpdmF0ZS1rZXktZm9ybWF0OiB2MS4zCkFsZ29yaXRobTogNSAoUlNBU0hBMSkKTW9kdWx1czogM1VkcWcyZm9DQTg0Zm1oOUNWenZ5blI2YjV6dTF6dVI3Nk81RGRpZkdRaE9xT2VzOTNsczJvNGp6eFdUeGErZWEyeGJzRmJtVkdxYjBoakt5SzBoYUNnSlNJVGhYWkdhTG9wY2REYjZqSVBJK1JMQ3IvbStDeVJyU25Ud3hNTHZsbVVMQTdXN0J5UXR5WmNmcjZkUWhDK3FIcEx4RzNsOVlWQXRTcCtWQ0UwPQpQdWJsaWNFeHBvbmVudDogQVFBQgpQcml2YXRlRXhwb25lbnQ6IGhvcnQwSWhWSk5GY1lEL1lCdUZqUzQ0WEE5WS93czZOcFUrL0xSUVJhSDhNbE5hSTdNLy94OE8xTWl6RWRPYWJSR1hXT2hvY1lpZVFKdWE4SmRoZS9ud29OdFh0YzBFMXdheFZ0ZkkyeUlXRVpQS3VldVZsdFhYT2Y1aWpDYzE5WkJzc1M5S3g5R00wQlpTaFFTTTl0UGpqaEdTekxUSUNhMDA0WWloVXFRRT0KUHJpbWUxOiA4QUVMaXNhMGdhOGk2ZFhmZDFnMVNMK092U2hobXFldGZhMEx4dHVnaHhsUm96STJUSng4WTQyM3VxSS9BNVZLWXVyNE5ZVDNvVnpBQXZtU0NSeVBoUT09ClByaW1lMjogN0FiaDk4T0pxeEwyQnhBeitNRmRyY1ZhSnByOVpoL29NTVAzWm5qVkx6THNqeXNrNUZQL3Z4U3VRTVVNU1gwV1piOVNUbmdhV3F5TG5YVXo0V21jS1E9PQpFeHBvbmVudDE6IDVieEtYUnZadTIxMjRSaXRvT0xabG5wdTJ0aGxuWkcxKzJBQ3J1YWE0ZGMxa3g3RVpVOUJybFlBc2ZFT21wSjBNdjJ5ZkNCOG5ZUlg5RUVMTGhlZHRRPT0KRXhwb25lbnQyOiB2VWJYdDZWcnBYRlRNMTdmRHNHaXFsUDFjN2dmTmVLb2hWTGg5NTgyOXQ3VHJneGZUV3UvVURENWZKK0l0dlpGRzl0TjJmZWV5dEJNTmoxakdZVmo0UT09CkNvZWZmaWNpZW50OiBEWGRJSURTdVN5cEtENFVrUEhzeFE1eWM2c2s4TkFVajBHbERMUmFTTWVPNk9rV0QwVTZadUxlQldodEtlQ2dURXRQRzNadDl2NU5ZWGYyV1p4YjFuQT09Cg==",
					},
				},
				KSK: []tc.DNSSECKeyV11{
					{
						InceptionDateUnix:  1622818189,
						ExpirationDateUnix: 1628002189,
						Name:               "defaultds2.test1.host.",
						TTLSeconds:         60,
						Status:             "new",
						EffectiveDateUnix:  1622818189,
						Public:             "ZGVmYXVsdGRzMi50ZXN0MS5ob3N0Lgk2MAlJTglETlNLRVkJMjU3IDMgNSBBd0VBQWRZR2NyUDRtU2JONzZldVhZYVhmWnVqYTBYYjNQZUNsQVV4MzBFUi9YTjFoZVNWT3FRd0orQXA2VDVONDltS2o1QUJIQ1RZb1FGT0RSenpWdHFRbjduSGlnSXV0NFhpQWRTaDgzZkg5ekNpV3IvOERyd0VHMnZkb3pETGxpY3BaNVFLOWJicUhabllzNjhhRitaelFFOU5xZ1RIVDhFYlhJODdiWHFtMzVDUzRWb1o4NythUGtVWmpUVUN5V0YrS29kcTFVaExtQzVNMmVrQzNsb0lzZVordnRiVWtrMWJUQWpkQlFCL3RQZjRjczJqYmloQTJ6eWZyRmprU3dPdlpDOFVVWkY0NWdMTFFVTXhPUVFROWRtVkVUVTF5NFVpYW5iZXJmckk5L2FtMUxnNlpyajFKYVByZlhRWXlYcnhMWE1wajUzQmxiMWZIdkc5WmgyVmJvYz0=",
						Private:            "UHJpdmF0ZS1rZXktZm9ybWF0OiB2MS4zCkFsZ29yaXRobTogNSAoUlNBU0hBMSkKTW9kdWx1czogMWdaeXMvaVpKczN2cDY1ZGhwZDltNk5yUmR2Yzk0S1VCVEhmUVJIOWMzV0Y1SlU2cERBbjRDbnBQazNqMllxUGtBRWNKTmloQVU0TkhQTlcycENmdWNlS0FpNjNoZUlCMUtIemQ4ZjNNS0phdi93T3ZBUWJhOTJqTU11V0p5bG5sQXIxdHVvZG1kaXpyeG9YNW5OQVQwMnFCTWRQd1J0Y2p6dHRlcWJma0pMaFdobnp2NW8rUlJtTk5RTEpZWDRxaDJyVlNFdVlMa3paNlFMZVdnaXg1bjYrMXRTU1RWdE1DTjBGQUgrMDkvaHl6YU51S0VEYlBKK3NXT1JMQTY5a0x4UlJrWGptQXN0QlF6RTVCQkQxMlpVUk5UWExoU0pxZHQ2dCtzajM5cWJVdURwbXVQVWxvK3Q5ZEJqSmV2RXRjeW1QbmNHVnZWOGU4YjFtSFpWdWh3PT0KUHVibGljRXhwb25lbnQ6IEFRQUIKUHJpdmF0ZUV4cG9uZW50OiBWRlNnRjVmSnlNZDJPY3p6bnhmTDcycDUxMEhsbEVVSVMrKzF0eTcrZmVMOXllNmU5NWpkN1c2Mkw4MkREUEdTMWJ3S09kNTl1a1RsMTlWdUVKclJ4T01CMXhCUFVkcVd2QkRBSFI5V24vd280K0xPYjNqeTBSSzR2WDVLZ00zSXVVV0VRZm1IaGxvam1zZ2VTTGg2eTRTZmpGaDRiVzk1amhwdGJkbVkxNTYvMCtkckdESFhjY0RRWWtEd2g3Sk1VbVU1YTltMlUydDQva2lxTjE4TmU2dFRWbkU2d2Z0WGk3Z1FvblRqaTZTcTYwTmQxNFBIK3F1a3llTUVrLzdQcTM5SGoxcUNmSWxZZ3ZCeW1Dc3NMUTdOMmtRemlxQXpMUWVVejJGMStDMmo3ME1YaWRHK2JOVHpOaHJjY00vVHNwQmdmYVdkWXZTSThzb0c1UzFqOFE9PQpQcmltZTE6IDQvKzRxaWpBa3MwMkdsSGxqcmJjdzZiS3J4UTRDWnZ5RCtKMUdFeFFLL0laMVU0M0tpcWJaSHVBSmxXcWl1VEdwZDluUnZxZGF2amNRQ0lmVE1vV1FJa2M4OHZpb2JXU2drMTZVSksydGIybURDZW5FcGttQWFZMkdRSERnMUk0UmdLSHJkZDJReDVRekhaVWR3QjhVU090MjIzSkZBWm03UHozNldjM04zOD0KUHJpbWUyOiA4RTlrclkxbk9Hb2l2SElhK0pOc29hRDBhc0ZwODl1ckJDUk1VWjRVb2VKWDVVTmZVMWhBcUZ5dVJHZm1oZXRyUEEybUFvZFp5UUhVMnpPckg2N3p1VGpvSTJ4N2d1K0NlU1VtMCtWR2EzTUQ2eWhuTXRUanhxZkVaQ3NTbG5ZWmNCUGJqdmVDMC91WHZKYjJNVHN4NDQyd3luYU9DS25hd3pLYzdIVDVqUGs9CkV4cG9uZW50MTogR290VkpvcGtFVE5QRHpWbHNuM2JxZk9yT1VMeld6c0tyWXJCOHpnL1JUNkVmMjhCd1NrQXVtd2VlVmdUNk9QRnRONFRtaEhuYmVMWFVhZ25XTHRXWitFT3U5dUs0U1RRajljUlhId1lSWVIwNW9sZlRDMEVYY0RLSDVNeS9nRCtpRGdYTDhnYi9xaHk0N3NMRG1mQ0VYaEQ3MzRTb1FBMXozV01MMkpTN1dVPQpFeHBvbmVudDI6IFV4cWhyb01nRnhwZE9ONGRCYW0xLzQ4eDkxazcwdUU4bXdvU2VvYzRpMk5ERWozaVVXaExzKzJaTm43WDhhZ2dSWHhTMUwwS0I4RmlZd3ZUT2ZtK3YyYzJvRWw3elNRVzh0NHVOMGtxdVMzbFJRV0w2c0JFcFFhUG5EUnBFUzkyVEpRUmNiZVd2c2hiQ1JVTHZxckI3ZmVxRTlvNzlETUpQRWZjak1sSEk4RT0KQ29lZmZpY2llbnQ6IFYvbmQ2RDFUNlA0cnlMbDBza0FkSHRlQTNkRHl3M3JxVmJWYUtSRWhtdkVJTjhvM01SUkZlUTNiZDdTbld3bzJrQnA1SmJYajlJT3IyT09jWGhNVzlOSzZDRlFRREtDVGc1aWZmZXZJQXMrM2hpSVhmT0p6dEZhY0JROFhUVlUwRFpiUzFSN1NxVlp6dC9RZ2t3ZFNIcHpIS1EwRk00aXI2M1JkWWM0N0xZZz0K",
					},
				},
			},
		},
	}

	if errs := backend.ValidateKey(); errs != nil && len(errs) > 0 {
		t.Fatalf("expected no valdiation issues with blank struct got: %v\n", strings.Join(errs, ", "))
	}

	if err := backend.SetSSLKeys([]SSLKey{sslkey}); err != nil {
		t.Fatal(err)
	}
	if err := backend.SetURISignKeys([]URISignKey{uri}); err != nil {
		t.Fatal(err)
	}
	if err := backend.SetURLSigKeys([]URLSigKey{url}); err != nil {
		t.Fatal(err)
	}
	if err := backend.SetDNSSecKeys([]DNSSecKey{dnssec}); err != nil {
		t.Fatal(err)
	}

	if errs := backend.ValidateKey(); errs != nil && len(errs) > 0 {
		t.Fatalf("expected no valdiation issues with filled struct got: %v\n", strings.Join(errs, ", "))
	}

	keys, err := backend.GetSSLKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatal("expected one key, got: " + strconv.Itoa(len(keys)))
	}
	if !reflect.DeepEqual(keys[0], sslkey) {
		t.Fatal("expected ssl key to be the same")
	}

	uriKeys, err := backend.GetURISignKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(uriKeys) != 1 {
		t.Fatal("expected one uri key, got: " + strconv.Itoa(len(uriKeys)))
	}
	if !reflect.DeepEqual(uriKeys[0], uri) {
		t.Fatal("expected uri key to be the same")
	}

	urlKeys, err := backend.GetURLSigKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(urlKeys) != 1 {
		t.Fatal("expected one url key, got: " + strconv.Itoa(len(urlKeys)))
	}
	if !reflect.DeepEqual(urlKeys[0], url) {
		t.Fatal("expected url key to be the same")
	}

	dnssecKeys, err := backend.GetDNSSecKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(dnssecKeys) != 1 {
		t.Fatal("expected one dnssec key, got: " + strconv.Itoa(len(dnssecKeys)))
	}
	if !reflect.DeepEqual(dnssecKeys[0], dnssec) {
		t.Fatal("expected dnssec key to be the same")

	}
}

func TestRiakBackend(t *testing.T) {
	riak := RiakBackend{}
	testBackend(t, &riak)
}

func TestPGBackend(t *testing.T) {
	data := make([]byte, 32)
	for i, _ := range data {
		data[i] = byte('a' + rune(rand.Intn(26)))
	}
	pg := PGBackend{
		cfg: PGConfig{
			AESKey: data,
		},
	}
	testBackend(t, &pg)

	if err := insertIntoTable(nil, "TEST", 1, make([]interface{}, 0)); err != nil {
		t.Fatal(err)
	}
}
