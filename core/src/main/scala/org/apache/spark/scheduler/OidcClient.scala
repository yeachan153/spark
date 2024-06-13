/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.scheduler

import java.io.File
import java.text.SimpleDateFormat
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.fasterxml.jackson.module.scala.experimental.ScalaObjectMapper
import org.apache.spark.SparkConf
import org.apache.spark.internal.config._

import java.util.Date

class OidcClient(conf: SparkConf) {

  private var token: Option[OidcToken] = None

  private val SSO_TIMEOUT = conf.get(OIDC_SSO_TIMEOUT)
  private var initialRemainingTimeMinutes: Option[Long] = None
  private var initialRemainingTimeTimestamp: Option[Long] = None
  private var timeoutMessage: Option[String] = None
  private var refreshTokenFailureReason: Option[String] = None

  private val enabled = conf.get(OIDC_ENABLED)
  private lazy val oidcRequests: OidcClientRequests = {
    if (enabled) new OidcClientRequests(conf)
    else throw new IllegalStateException("OIDC mode is disabled")
  }
  private val jwtParser = new Jwt()
  private val tokenRefreshInterval = conf.get(OIDC_TOKEN_REFRESH_INTERVAL)
  private val tokenPath = conf.get(OIDC_TOKEN_PATH)
  private val millisecondsInSeconds = 1000
  private val secondsInMinute = 60
  private val minutesInHour = 60


  private var isInitialLogin: Boolean = true

  val retries = 5
  val retriesWaitingForUser = 60
  val retriesRefreshToken = 3
  val retriesDelay = 5

  def getToken: Option[OidcToken] = token

  def oidcEnabled: Boolean = enabled

  def getTokenRefreshInterval: Int = tokenRefreshInterval

  def getOidcRefreshRunnable: Runnable = new Runnable() {
    override def run(): Unit = {
      try {
        refreshToken()
        persistToken()
      } catch {
        case e: Exception =>
          System.err.println(s"Error occured while refreshing token: ${e.getMessage}")
      }
    }
  }

  private def printRemainingAuthTime(authTime: Long): Unit = {
     if (SSO_TIMEOUT > 0) {
       val issueDate = new Date(authTime * millisecondsInSeconds)
       val expiryDate = new Date(issueDate.getTime() + SSO_TIMEOUT * millisecondsInSeconds)
       val currentDate = new Date()
       val dtFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm")
       val remainingTime = expiryDate.getTime() - currentDate.getTime()

       val remainingHours = remainingTime / (millisecondsInSeconds * minutesInHour * secondsInMinute)
       val remainingMinutes = (remainingTime % (millisecondsInSeconds * minutesInHour * secondsInMinute)) / (millisecondsInSeconds * secondsInMinute)

       System.err.println(s"Authentication will expire in $remainingHours hours and $remainingMinutes minutes from ${dtFormat.format(currentDate)}")

       if (isInitialLogin) {
        initialRemainingTimeMinutes = Some(remainingTime / (millisecondsInSeconds * secondsInMinute))
        initialRemainingTimeTimestamp = Some(System.currentTimeMillis() / millisecondsInSeconds)
       }
     }
  }

  private def fetchTokenFromDevice(): OidcToken = {
    val deviceAuthzResponse = Retry.withDelay(retries, retriesDelay) {
      oidcRequests.deviceAuthzRequest()
    }

    System.err.println(s"************PLEASE VISIT ${deviceAuthzResponse.verification_uri_complete} TO AUTHENTICATE************")

    val deviceTokenResponse = Retry.withDelay(retriesWaitingForUser, retriesDelay) {
      oidcRequests.deviceTokenRequest(deviceAuthzResponse.device_code)
    }
    printRemainingAuthTime(jwtParser.getLongAttribute(deviceTokenResponse.accessToken, "auth_time"))
    deviceTokenResponse
  }

  private def fetchTokenFromUsername(): OidcToken = {
    val tokenResp = Retry.withDelay(retries, retriesDelay) {
      oidcRequests.ropcTokenRequest()
    }
    tokenResp
  }

  private def fetchTokenFromRefreshToken(oldToken: OidcToken): OidcToken = {
    val tokenResp = oidcRequests.refreshTokenRequest(oldToken.refresh_token, oldToken.session_state)
    tokenResp
  }

  def persistToken(): Unit = {
    val objectMapper = new ObjectMapper() with ScalaObjectMapper
    objectMapper.registerModule(DefaultScalaModule)
    objectMapper.writeValue(new File(tokenPath), token.get)
  }

  private def fetchNewToken(): OidcToken = {
    if ((conf.get(OIDC_USERNAME).nonEmpty && conf.get(OIDC_PASSWORD).nonEmpty) ||
      (sys.env.contains("OIDC_USERNAME") && sys.env.contains("OIDC_PASSWORD"))) {
      fetchTokenFromUsername()
    } else {
      // TODO: Disabling device-flow re-login for now because the re-authentication is quite confusing, users
      // get the authentication message in the middle of their stack trace. It's also difficult to
      // stop Spark re-trying it's own tasks until the user re-authenticates by re-clicking the
      // device flow link. For now making it clear to the user that the best option is to restart
      // the spark session.
      if (!isInitialLogin) {
        if (timeoutMessage.isEmpty) {
          val initialTimeMinutes = initialRemainingTimeMinutes.get
          val currentTimestamp = System.currentTimeMillis() / millisecondsInSeconds
          val elapsedMinutes = (currentTimestamp - initialRemainingTimeTimestamp.get) / secondsInMinute
          val refreshTokenFailure = refreshTokenFailureReason.get

          timeoutMessage = Some(
            s"""Reauthenticate by restarting the kernel and spark session.
                |Initial remaining authentication time was: $initialTimeMinutes minutes. 
                |Elapsed time since initial authentication: $elapsedMinutes minutes.
                |Attempted to retry $retriesRefreshToken times to fetch new access token
                |with refresh token, but failed with $refreshTokenFailure""".stripMargin)
        }
        throw new IllegalStateException(timeoutMessage.get)
      }
      fetchTokenFromDevice()
    }
  }

  def refreshToken(): OidcToken = {
    token = token match {
      case Some(token) => {
        try {
          // Adding a retry as some users claim they experienced token expiry before
          // it should actually expire.
          Option(Retry.withDelay(retriesRefreshToken) {fetchTokenFromRefreshToken(token)})
        } catch {
          case e: InvalidRefreshTokenException =>
            refreshTokenFailureReason = Some(s"${e.getMessage}")
            Option(fetchNewToken())
        }
      }
      case None => {
        val newToken = Option(fetchNewToken())
        isInitialLogin = false
        newToken
      }
    }
    token.get
  }
}
