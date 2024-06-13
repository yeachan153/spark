package org.apache.spark.scheduler

import org.apache.spark.SparkConf
import org.apache.spark.internal.config._

class OidcClientRequests(conf: SparkConf) {

  private val username: Option[String] = {
    val user = Option(conf.get(OIDC_USERNAME)).filter(_.nonEmpty).map(_.toString)
    user.orElse(sys.env.get("OIDC_USERNAME"))
  }
  private val password: Option[String] = {
    val user = Option(conf.get(OIDC_PASSWORD)).filter(_.nonEmpty).map(_.toString)
    user.orElse(sys.env.get("OIDC_PASSWORD"))
  }
  private val clientId = conf.get(OIDC_CLIENT)
  private val clientSecret = Option(conf.get(OIDC_CLIENT_SECRET))
  private val (tokenUrl, deviceUrl) = {
    val tokenUrlResp = requests.get(conf.get(OIDC_CONNECT_DISCOVERY_URL))
    val tokenUrl = ujson.read(tokenUrlResp.text())("token_endpoint").str
    val deviceUrl = ujson.read(tokenUrlResp.text())("device_authorization_endpoint").str
    (tokenUrl, deviceUrl)
  }

  def deviceAuthzRequest(): DeviceAuthzResponse = {
    val data = Map.empty[String, String] ++
      Map("client_id" -> clientId) ++
      clientSecret.map(cs => Map("client_secret" -> cs)).getOrElse(Map.empty)

    val deviceAuthResp = requests.post(
      deviceUrl,
      headers = Map("Content-Type" -> "application/x-www-form-urlencoded"),
      data = data,
      check = false
    )
    if (deviceAuthResp.statusCode < 200 || deviceAuthResp.statusCode > 299)
      throw new DeviceAuthorizationException(
        s"Device Authorization Request failed with message ${deviceAuthResp.statusCode} ${deviceAuthResp.statusMessage}"
      )
    val deviceJson = ujson.read(deviceAuthResp.text())
    DeviceAuthzResponse(
      deviceJson("verification_uri_complete").str,
      deviceJson("device_code").str
    )
  }

  def deviceTokenRequest(deviceCode: String): OidcToken = {
    val data = Map.empty[String, String] ++
      Map(
        "grant_type" -> "urn:ietf:params:oauth:grant-type:device_code",
        "client_id" -> clientId,
        "device_code" -> deviceCode)

    val tokenJsonResp = requests.post(
      tokenUrl,
      headers = Map("Content-Type" -> "application/x-www-form-urlencoded"),
      data = data,
      check = false
    )
    if (tokenJsonResp.statusCode < 200 || tokenJsonResp.statusCode > 299) {
      throw new TokenFetchException(
        s"Device Access Token Request failed with message ${tokenJsonResp.statusCode} ${tokenJsonResp.statusMessage}. " +
        "Likely to have timed out after waiting for user to click the device auth link. Please restart the kernel & try again."
      )
    }
    val tokenJson = ujson.read(tokenJsonResp.text())
    OidcToken(
      tokenJson("accessToken").str,
      tokenJson("refresh_token").str,
      tokenJson("session_state").str
    )
  }

  def ropcTokenRequest(): OidcToken = {
    val data = Map(
      "grant_type" -> "password",
      "client_id" -> clientId,
      "username" -> username.get,
      "password" -> password.get,
    ) ++ clientSecret.map(cs => Map("client_secret" -> cs)).getOrElse(Map.empty)

    val tokenJsonResp = requests.post(
      tokenUrl,
      headers = Map("Content-Type" -> "application/x-www-form-urlencoded"),
      data = data,
      check = false
    )
    if (tokenJsonResp.statusCode < 200 || tokenJsonResp.statusCode > 299)
      throw new TokenFetchException(
        s"Resource Owner Password Credentials Grant Request failed " +
          s"with message ${tokenJsonResp.statusCode} ${tokenJsonResp.statusMessage}"
      )
    val tokenJson = ujson.read(tokenJsonResp.text())
    OidcToken(
      tokenJson("accessToken").str,
      tokenJson("refresh_token").str,
      tokenJson("session_state").str
    )
  }

  def refreshTokenRequest(refreshToken: String, sessionState: String): OidcToken = {
    val secret = clientSecret match {
      case Some(clientSecret) => clientSecret
      case None => sessionState
    }
    val data = Map("grant_type" -> "refresh_token", "client_id" -> clientId,
      "client_secret" -> secret, "refresh_token" -> refreshToken)

    val tokenJsonResp = requests.post(
      tokenUrl,
      headers = Map("Content-Type" -> "application/x-www-form-urlencoded"),
      data = data,
      check = false
    )
    val tokenJson = ujson.read(tokenJsonResp.text())
    if (tokenJsonResp.statusCode < 200 || tokenJsonResp.statusCode > 299)
      throw new InvalidRefreshTokenException(
        s"Refresh Token Request returned error ${tokenJsonResp.text()}, status code: ${tokenJsonResp.statusCode}, status message: ${tokenJsonResp.statusMessage}"
      )
    OidcToken(
      tokenJson("accessToken").str,
      tokenJson("refresh_token").str,
      tokenJson("session_state").str
    )
  }
}

object Retry {

  /** Retries function if it threw an error.
   *
   * @example {{{
   *    // Retry 5 times every 10 seconds
   *    val result = retry(5, 10) {
   *      sendRequest()
   *    }
   * }}}
   * */
  def withDelay[T](max: Int, delay: Int = 5)(f: => T): T = {
    var tries = 0
    var response: Option[T] = None

    while (response.isEmpty) {
      try {
        response = Some(f)
      } catch {
        case e: Throwable => {
          tries += 1
        }
          if (tries > max)
            throw e
          else {
            Thread.sleep(delay * 1000)
          }
      }
    }
    response.get
  }
}
