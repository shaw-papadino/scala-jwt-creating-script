//> using lib com.nimbusds:nimbus-jose-jwt:9.37.3
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT

import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Date

object JWTCreator {
  def main(args: Array[String]): Unit = {
    if (args.length < 3 || args.length % 2 != 1) {
      println("Usage: scala JWTCreatorVerifier <issuer> <subject> <keyID> [<key1:value1> <key2:value2> ...]")
      System.exit(1)
    }

    val issuer = args(0)
    val subject = args(1)
    val keyID = args(2)
    
    val customClaims = args.drop(3).grouped(2).map { case Array(k, v) => k -> v }.toMap

    val keyPairGen = KeyPairGenerator.getInstance("RSA")
    keyPairGen.initialize(2048)
    val keyPair = keyPairGen.generateKeyPair()

    val privateKey: RSAPrivateKey = keyPair.getPrivate.asInstanceOf[RSAPrivateKey]
    val publicKey: RSAPublicKey = keyPair.getPublic.asInstanceOf[RSAPublicKey]

    val now = new Date()
    val expirationTime = new Date(now.getTime + 3600000)

    val claimsBuilder = new JWTClaimsSet.Builder()
      .issuer(issuer)
      .subject(subject)
      .issueTime(now)
      .expirationTime(expirationTime)

    customClaims.foreach { case (k, v) =>
      claimsBuilder.claim(k, v)
    }

    val claimsSet = claimsBuilder.build()

    val signer = new RSASSASigner(privateKey)

    val signedJWT = new SignedJWT(
      new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyID).build(),
      claimsSet
    )

    signedJWT.sign(signer)

    val serializedJWT = signedJWT.serialize()

    println(s"Generated JWT: $serializedJWT")
  }
}

