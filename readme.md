# 1 Program to generate JWE

This program is meant to test encryption of a payload to verify a JWE based solution.

It is also partially created using promts to chatgpt, as inspiration.

Binaries will not be provided for this project.

# 2 Running

## 2.1 TL;DR Quickguide

If you just want to encrypt something or decrypt something, follow these steps:
1. Either generate a keypair (see testing for command line) or copy your own to the resources folder
1. Update application.yaml appropriately to match the key chosen above
1. Encrypting
    1. Update the default payload in JweGenerator.java if you want.
    1. Execute `mvn compile exec:java -Dexec.mainClass=dk.kodeninjaer.java.crypto.jwe.JweGenerator` to generate a JWE for testing
1. Decrypting
    1. Update the encrypted payload in JweDecryptor.java
    1. Execute `mvn compile exec:java -Dexec.mainClass=dk.kodeninjaer.java.crypto.jwe.JweDecryptor` to Decrypt your encrypted JWE

## 2.2 Prerequisites
* Java 21
* Maven 3.9.9 or newer


# 3 Testing

## 3.1 Create test certificate

```sh
# go to src/main/resources and make a terminal

keytool -genkeypair \
  -alias mykey \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -validity 3650 \
  -storepass changeit \
  -keypass changeit \
  -dname "CN=JWEEncTest, OU=CrytpoNinja, O=kodeninjaer.dk, L=Praestoe, C=DK"
```


