package io.dronekit.oauth

import collection.mutable.Stack
import org.scalatest._
import org.scalatest.concurrent._
import scala.concurrent.duration._
import scala.concurrent.Future
import io.dronekit.oauth

class OauthSpec extends FunSpec with Matchers {
  describe("Oauth") {
    val uri = "http://oauthbin.com"

    it("can generate a request token header"){
      val oauth = new Oauth(key="key", secret="secret")
      assert("""OAuth oauth_signature_method="HMAC-SHA1",oauth_signature="MaF4i5B0coA78m9Vieoks2vhRUQ%3D",oauth_consumer_key="key",oauth_version="1.0",oauth_callback="oob",oauth_timestamp="1437716634",realm="http://oauthbin.com/v1/request-token",oauth_nonce="VjIWYTzy8o1437716634"""" ==
        oauth.getRequestTokenHeader(uri+"/v1/request-token", nonce="VjIWYTzy8o1437716634", epoch="1437716634"))
    }

    it("can generate an auth token header") {
      val oauth = new Oauth(key="key", secret="secret")
      oauth.setRequestTokens("requestkey", "requestsecret")
      assert("""OAuth oauth_signature_method="HMAC-SHA1",oauth_verifier="",oauth_signature="P0DVFf8rdrb1a4GCTbeAaKMGrio%3D",oauth_consumer_key="key",oauth_version="1.0",oauth_token="requestkey",oauth_timestamp="1437716636",realm="http://oauthbin.com/v1/access-token",oauth_nonce="2Xm0M1N8XT1437716636""""
        == oauth.getAccessTokenHeader(uri+"/v1/access-token", nonce="2Xm0M1N8XT1437716636", epoch="1437716636"))
    }

    it("can generate a signed request token") {
      val oauth = new Oauth(key="key", secret="secret")
      oauth.setAccessTokens("accesskey", "accesssecret")
      assert("""OAuth oauth_signature_method="HMAC-SHA1",oauth_signature="RQm%2BFjdYdHH%2BQzmlGK7w8cznYSE%3D",oauth_consumer_key="key",oauth_version="1.0",oauth_token="accesskey",oauth_timestamp="1437716637",oauth_nonce="60RgxveTVS1437716637""""
        == oauth.getSignedHeader(uri+"/v1/echo", method="GET", params=Map("a"->"1", "b"->"2"), nonce="60RgxveTVS1437716637", epoch="1437716637"))
    }

  }
}
