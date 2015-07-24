#Scala Oauth Headers
Generates Oauth 1.0a oauth headers.

This package only generates the headers. Combine it with whatever http lib to actually send the Oauth request.

##Usage

```scala
import io.dronekit.oauth._

val uri = "http://oauthbin.com"
val oauth = new Oauth(key="key", secret="secret")

// get the request token header
oauth.getRequestTokenHeader(uri+"/v1/request-token")

// send this off with some http request and get back a request token/key
// set the key
oauth.setRequestTokens("requestkey", "requestsecret") // optional verifier as a 3rd argument

// get the access token header
oauth.getAccessTokenHeader(uri+"/v1/access-token")

// send off a request to get the access token/secret
// set the access token key/secret
oauth.setAccessTokens("accesskey", "accesssecret")

// now get signed headers for any requests
oauth.getSignedHeader(uri+"/v1/echo", method="GET", params=Map("a"->"1", "b"->"2")
oauth.getSignedHeader(uri+"/v1/echo", method="POST", params=Map("c"->"3", "d"->"4")
```


##Importing via sbt

1. clone down this repo
2. `sbt publish-local`
3. add the following to `build.sbt`
  ```
  libraryDependencies += "io.dronekit" %% "oauth-headers" % "0.1"
  ```

##Testing

`sbt test`
