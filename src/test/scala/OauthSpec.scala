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
      val controlHeader =
        """
          |OAuth oauth_signature_method="HMAC-SHA1",
          |oauth_signature="MaF4i5B0coA78m9Vieoks2vhRUQ%3D",
          |oauth_consumer_key="key",oauth_version="1.0",
          |oauth_callback="oob",
          |oauth_timestamp="1437716634",
          |realm="http://oauthbin.com/v1/request-token",
          |oauth_nonce="VjIWYTzy8o1437716634"
          |""".stripMargin.replace("\n", "")
      val testHeader = oauth.getRequestTokenHeader(
        s"$uri/v1/request-token", nonce="VjIWYTzy8o1437716634", epoch="1437716634")
      assert(controlHeader == testHeader)
    }

    it("can generate an auth token header") {
      val oauth = new Oauth(key="key", secret="secret")
      oauth.setRequestTokens("requestkey", "requestsecret")

      val controlHeader =
        """
          |OAuth oauth_signature_method="HMAC-SHA1",
          |oauth_signature="izrd8vZ2aA67smgS2ioq4MhOHG8%3D",
          |oauth_consumer_key="key",
          |oauth_version="1.0",
          |oauth_token="requestkey",
          |oauth_timestamp="1437716636",
          |realm="http://oauthbin.com/v1/access-token",
          |oauth_nonce="2Xm0M1N8XT1437716636"
          |""".stripMargin.replace("\n", "")
      val testHeader = oauth.getAccessTokenHeader(
        s"$uri/v1/access-token", nonce="2Xm0M1N8XT1437716636", epoch="1437716636")
      assert(controlHeader == testHeader)
    }

    it("can generate a signed request token") {
      val oauth = new Oauth(key="key", secret="secret")
      oauth.setAccessTokens("accesskey", "accesssecret")
      val controlHeader =
        """
          |OAuth oauth_signature_method="HMAC-SHA1",
          |oauth_signature="RQm%2BFjdYdHH%2BQzmlGK7w8cznYSE%3D",
          |oauth_consumer_key="key",
          |oauth_version="1.0",
          |oauth_token="accesskey",
          |oauth_timestamp="1437716637",
          |oauth_nonce="60RgxveTVS1437716637"
          |""".stripMargin.replace("\n", "")
      val testHeader = oauth.getSignedHeader(
        s"$uri/v1/echo", method="GET", params=Map("a"->"1", "b"->"2"), nonce="60RgxveTVS1437716637", epoch="1437716637")
      assert(controlHeader == testHeader)
    }

    it("can generate a hash with keys that need to be escaped") {
      val oauth = new Oauth(key="207e4f25-31d0-4032-8312-ce3b4e738b48", secret="956f6ff3-f2da-4016-9ba7-e446e640cf4b")
      val testStr =  "POST&http%3A%2F%2Foauthbin.com%2Fv1%2Fecho&clientID%3DHauIUgRcEFaiknNVOf6bsXYxs6M%26file%255B0%255D%3Dhttp%253A%252F%252Finspector-gadget.s3.amazonaws.com%252FFortMason%252FImages%252FG0040389.JPG%26file%255B1%255D%3Dhttp%253A%252F%252Finspector-gadget.s3.amazonaws.com%252FFortMason%252FImages%252FG0040390.JPG%26oauth_consumer_key%3Dkey%26oauth_nonce%3Dec51043fc194a44b87e782cc73537a7353b7e361%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1438198255%26oauth_token%3Daccesskey%26oauth_version%3D1.0%26photosceneid%3DHQuTpwTYHZKbnnjDDQolRmhzVBE%26type%3Dimage"
      val hash = oauth.getHash(testStr, "secret", "asdf")
      assert(hash === "vhm4LWRV2D9q19PrAU2AiNQhQ8w=")
    }

    it("can return a token entity") {
      val oauth = new Oauth(key="key", secret="secret")
      oauth.setAccessTokens("accessKey", "accessSecret")
      val tokenEntity = oauth.getTokens()
      assert(tokenEntity.key === "accessKey")
      assert(tokenEntity.secret === "accessSecret")
    }

    it("can generate a hash with a callback url") {
      val oauth = new Oauth(key="MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", secret="MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98")
      val testStr = "POST&https%3A%2F%2Faccounts.autodesk.com%2FOAuth%2FRequestToken&oauth_callback%3Dhttp%253A%252F%252F6c9df4ff.ngrok.io%26oauth_consumer_key%3D207e4f25-31d0-4032-8312-ce3b4e738b48%26oauth_nonce%3D4HQuCpmhvF1440099378%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1440099378%26oauth_version%3D1.0"
      val hash = oauth.getHash(testStr, "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "")
      assert(hash === "JnxxIGGO3R2wXLLi9ut9uK/fAr0=")
    }
  }
}
