package org.apache.spark.scheduler

import com.fasterxml.jackson.annotation.JsonProperty

case class OidcToken(
                            @JsonProperty("accessToken") accessToken: String,
                            @JsonProperty("refresh_token") refresh_token: String,
                            @JsonProperty("session_state") session_state: String,
                         )

case class DeviceAuthzResponse(
                            @JsonProperty("verification_uri_complete") verification_uri_complete: String,
                            @JsonProperty("device_code") device_code: String
                          )
