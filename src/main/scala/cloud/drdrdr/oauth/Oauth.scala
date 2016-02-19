package cloud.drdrdr.oauth

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.net.URLEncoder

import org.apache.commons.codec.binary.Base64.encodeBase64

import scala.collection.immutable.SortedMap
import scala.util.Random

object AuthProgress extends Enumeration {
  val Unauthenticated, HasRequestTokens, HasAccessTokens, RequestRefreshTokens = Value
}

object Oauth {
  val signatureMethod = "HMAC-SHA1"
  def getNonce: String = Random.alphanumeric.take(10).mkString + (System.currentTimeMillis() / 1000).toString

  def encodeParams(params: Map[String, String]): Map[String, String] = {
    params.foldLeft(Map[String, String]()) {
      (encoded, item) => encoded + (URLEncoder.encode(item._1, "UTF-8") -> URLEncoder.encode(item._2, "UTF-8"))
    }
  }
}

case class TokenEntity(key: String, secret: String, verifier: String)

class Oauth(secret: String, key: String, callback: String="oob") {
  private var _token = ""
  private var _tokenSecret = ""
  private var _tokenVerifier = ""
  private var _sessionHandle = ""

  var authProgress = AuthProgress.Unauthenticated

  def hasKeys: Boolean = !secret.isEmpty && !key.isEmpty

  def setRequestTokens(token: String, secret: String){
    // sets the request tokens. changes state to access tokens.
    _token = token
    _tokenSecret = secret
    authProgress = AuthProgress.HasRequestTokens
  }

  def setVerifier(verifier: String) {
    _tokenVerifier = verifier
  }

  def setAccessTokens(token: String, secret: String, sessionHandle: String = "") {
    // after this is set, oauth can start making authenticated calls
    _token = token
    _tokenSecret = secret
    _sessionHandle = sessionHandle

    authProgress = if (sessionHandle.nonEmpty) {
      AuthProgress.RequestRefreshTokens
    } else {
      AuthProgress.HasAccessTokens
    }
  }

  def canSignRequests: Boolean = {
    authProgress == AuthProgress.HasAccessTokens
  }

  def getTokens: TokenEntity = {
    TokenEntity(_token, _tokenSecret, _tokenVerifier)
  }

  def getRequestTokenHeader(url: String, method: String="POST", nonce: String="", epoch: String=""): String = {
    val _nonce = if (!nonce.isEmpty) nonce else Oauth.getNonce
    val _epoch = if (!epoch.isEmpty) epoch else (System.currentTimeMillis()/1000).toString

    var params: Map[String, String] = Map(
      "oauth_consumer_key" -> URLEncoder.encode(key, "UTF-8"),
      "oauth_signature_method"->Oauth.signatureMethod,
      "oauth_timestamp" -> _epoch,
      "oauth_nonce"-> _nonce,
      "oauth_version" -> "1.0"
    )

    if (!callback.isEmpty) {
      params += (("oauth_callback", URLEncoder.encode(callback, "UTF-8")))
    }

    val signature = getSignature(method, url, params, secret)

    params += (("realm", url))
    params += (("oauth_signature", URLEncoder.encode(signature, "UTF-8")))
    // returns the auth header
    "OAuth " + params.map { x => x._1 + "=\"" + x._2 + "\"" }.mkString(",")
  }

  def getAccessTokenHeader(url: String, method: String="POST", nonce: String="", epoch: String=""): String = {
    val _nonce = if (!nonce.isEmpty) nonce else Oauth.getNonce
    val _epoch = if (!epoch.isEmpty) epoch else (System.currentTimeMillis()/1000).toString

    var params: Map[String, String] = Map("oauth_consumer_key"->URLEncoder.encode(key, "UTF-8"),
      "oauth_signature_method" -> Oauth.signatureMethod,
      "oauth_timestamp" -> _epoch,
      "oauth_nonce" -> _nonce,
      "oauth_version" -> "1.0",
      "oauth_token" -> URLEncoder.encode(_token, "UTF-8")
    )

    if (!_sessionHandle.isEmpty) {
      params += (("oauth_session_handle", URLEncoder.encode(_sessionHandle)))
    }

    if (!_tokenVerifier.isEmpty) {
      params += (("oauth_verifier", URLEncoder.encode(_tokenVerifier, "UTF-8")))
    }

    val signature = getSignature(method, url, params, secret, _tokenSecret)
    params += (("realm", url))
    params += (("oauth_signature", URLEncoder.encode(signature, "UTF-8")))

    "OAuth "+ params.map { x => x._1 + "=\"" + x._2 + "\"" }.mkString(",")
  }

  def getSignedHeader(url: String, method: String, params:Map[String, String] = Map(), nonce: String="", epoch: String="") = {
    val _nonce = if (!nonce.isEmpty) nonce else Oauth.getNonce
    val _epoch = if (!epoch.isEmpty) epoch else (System.currentTimeMillis()/1000).toString

    var baseParams: Map[String, String] = Map("oauth_consumer_key"->URLEncoder.encode(key, "UTF-8"),
      "oauth_signature_method" -> Oauth.signatureMethod,
      "oauth_timestamp" -> _epoch,
      "oauth_nonce" -> _nonce,
      "oauth_version" -> "1.0",
      "oauth_token" -> URLEncoder.encode(_token, "UTF-8")
    )

    val fullParams = baseParams ++ Oauth.encodeParams(params)
    val signature = getSignature(method, url, fullParams, secret, _tokenSecret)
    baseParams += (("oauth_signature", URLEncoder.encode(signature, "UTF-8")))

    "OAuth "+ baseParams.map { x => x._1 + "=\"" + x._2 + "\"" }.mkString(",")
  }

  def getHash(value: String, key: String, token: String=""): String = {
    // creates signature hash from token & key
    val keyString = URLEncoder.encode(key, "UTF-8") + "&" + URLEncoder.encode(token, "UTF-8")
    val keyBytes = keyString.getBytes
  	val signingKey = new SecretKeySpec(keyBytes, "HmacSHA1")
  	val mac = Mac.getInstance("HmacSHA1")
  	mac.init(signingKey)
  	val rawHmac = mac.doFinal(value.getBytes)
  	new String(encodeBase64(rawHmac))
  }

  def getSignature(method: String, url: String, params: Map[String, String], key: String, token: String=""): String = {
    // returns signature base string
    val sorted = SortedMap(params.toList:_*)

    val sigString = method.toUpperCase + "&" + URLEncoder.encode(url, "UTF-8") + "&" +
			URLEncoder.encode(sorted.map(p => p._1 + "=" + p._2).reduceLeft{(joined,p) => joined + "&" + p}, "UTF-8")

    getHash(sigString, key, token)
  }

}
