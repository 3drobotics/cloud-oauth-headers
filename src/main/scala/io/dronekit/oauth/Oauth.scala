package io.dronekit.oauth

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.apache.commons.codec.binary.Base64.encodeBase64

import scala.collection.immutable.SortedMap
import scala.util.Random

object AuthProgress extends Enumeration {
  val NotAuthed, HasRequestTokens, HasAccessTokens = Value
}

object Oauth {
  val signatureMethod = "HMAC-SHA1"
  def getNonce(): String = {
    Random.alphanumeric.take(10).mkString + (System.currentTimeMillis()/1000).toString()
  }

  def encodeParams(params: Map[String, String]): Map[String, String] = {
    params.foldLeft(Map[String, String]()) {(encoded, item) => encoded + (URLEncoder.encode(item._1) -> URLEncoder.encode(item._2))}
  }

  // def getBaseParams(key: String, token: String, epoch: String="", nonce: String=""): Map[String, String] = {
  //   val nonce = if (!nonce.isEmpty) nonce else getNonce()
  //   val epoch = if (!epoch.isEmpty) epoch else (System.currentTimeMillis()/1000).toString
  //
  //   Map("oauth_consumer_key"->key,
  //    "oauth_signature_method"->signatureMethod,
  //    "oauth_timestamp"->epoch,
  //    "oauth_nonce"->nonce,
  //    "oauth_version"->"1.0",
  //    "oauth_token"->token
  //  )
  // }
}

class Oauth(secret: String, key: String, callback: String="oob") {
  private var _token = ""
  private var _tokenSecret = ""
  private var _tokenVerifier = ""
  var authProgress = AuthProgress.NotAuthed

  def hasKeys: Boolean = !secret.isEmpty && !key.isEmpty

  def setRequestTokens(token: String, secret: String, verifier: String=""){
    // sets the request tokens. changes state to access tokens.
    _token = token
    _tokenSecret = secret
    _tokenVerifier = verifier
    authProgress = AuthProgress.HasRequestTokens
  }

  def setAccessTokens(token: String, secret: String) {
    // after this is set, oauth can start making authenticated calls
    _token = token
    _tokenSecret = secret
    authProgress = AuthProgress.HasAccessTokens
  }

  def canSignRequests: Boolean = {
    authProgress == AuthProgress.HasAccessTokens
  }

  def getRequestTokenHeader(url: String, method: String="POST", nonce: String="", epoch: String=""): String = {
    val _nonce = if (!nonce.isEmpty) nonce else Oauth.getNonce()
    val _epoch = if (!epoch.isEmpty) epoch else (System.currentTimeMillis()/1000).toString

    var params = Map(
      "oauth_consumer_key"->key,
      "oauth_signature_method"->Oauth.signatureMethod,
      "oauth_timestamp"->_epoch,
      "oauth_nonce"->_nonce,
      "oauth_version"->"1.0"
    )

    if (!callback.isEmpty) {
      params += (("oauth_callback", callback))
    }

    val signature = getSignature(method, url, params, secret)

    params += (("realm", url))
    params += (("oauth_signature", URLEncoder.encode(signature)))
    // returns the auth header
    "OAuth " + params.map { x => x._1 + "=\"" + x._2 + "\"" }.mkString(",")
  }

  def getAccessTokenHeader(url: String, method: String="POST", nonce: String="", epoch: String=""): String = {
    val _nonce = if (!nonce.isEmpty) nonce else Oauth.getNonce()
    val _epoch = if (!epoch.isEmpty) epoch else (System.currentTimeMillis()/1000).toString

    var params = Map("oauth_consumer_key"->URLEncoder.encode(key),
      "oauth_signature_method"->Oauth.signatureMethod,
      "oauth_timestamp"->_epoch,
      "oauth_nonce"->_nonce,
      "oauth_version"->"1.0",
      "oauth_token"->URLEncoder.encode(_token)
    )

    if (!_tokenVerifier.isEmpty) {
      params += (("oauth_verifier", URLEncoder.encode(_tokenVerifier)))
    }

    val signature = getSignature(method, url, params, secret, _tokenSecret)
    params += (("realm", url))
    params += (("oauth_signature", URLEncoder.encode(signature)))

    "OAuth "+(params.map{ x => x._1 + "=\""+ x._2+"\""}).mkString(",")
  }

  def getSignedHeader(url: String, method: String, params:Map[String, String] = Map(), nonce: String="", epoch: String="") = {
    val _nonce = if (!nonce.isEmpty) nonce else Oauth.getNonce()
    val _epoch = if (!epoch.isEmpty) epoch else (System.currentTimeMillis()/1000).toString

    var baseParams = Map("oauth_consumer_key"->URLEncoder.encode(key),
      "oauth_signature_method"->Oauth.signatureMethod,
      "oauth_timestamp"->_epoch,
      "oauth_nonce"->_nonce,
      "oauth_version"->"1.0",
      "oauth_token"->URLEncoder.encode(_token)
    )

    val fullParams = baseParams ++ Oauth.encodeParams(params)
    val signature = getSignature(method, url, fullParams, secret, _tokenSecret)
    baseParams += (("oauth_signature", URLEncoder.encode(signature)))
    // baseParams += (("oauth_consumer_key", URLEncoder.encode(key)))
    // baseParams += (("oauth_token", URLEncoder.encode(_token)))

    "OAuth "+(baseParams.map{ x => x._1 + "=\""+ x._2+"\""}).mkString(",")
  }

  def getHash(value: String, key: String, token: String=""): String = {
    // creates signature hash from token & key
    val keyString = URLEncoder.encode(key) + "&" + URLEncoder.encode(token)
    val keyBytes = keyString.getBytes()
  	val signingKey = new SecretKeySpec(keyBytes, "HmacSHA1")
  	val mac = Mac.getInstance("HmacSHA1")
  	mac.init(signingKey)
  	val rawHmac = mac.doFinal(value.getBytes())
  	return new String(encodeBase64(rawHmac))
  }

  def getSignature(method: String, url: String, params: Map[String, String], key: String, token: String=""): String = {
    // returns signature base string
    val sorted = SortedMap(params.toList:_*)

    val sigString = method.toUpperCase() + "&" + URLEncoder.encode(url) + "&" +
			URLEncoder.encode(sorted.map(p => p._1 + "=" + p._2).reduceLeft{(joined,p) => joined + "&" + p})
    getHash(sigString, key, token)

  }

}
