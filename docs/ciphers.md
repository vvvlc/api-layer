## Setting Ciphers for API ML Services

You can override ciphers that are used by the HTTPS servers in API ML services by configuring properties of the gateway, discovery service, and API catalog.

**Note:** You do not need to rebuild JAR files, when you override the default values in shell scirpts. 

The `application.yml` file contains the default value for each service, and can be found [here](/gateway-service/src/main/resources/application.yml). The default configuration gets packed in jar files. 
On z/OS, the default configuration can be overridden in `$ZOWE_ROOT_DIR/api-mediation/scripts/api-mediation-start-*.sh`, where `*` expands to `gateway`, `catalog`, and `discovery`.
Add the launch parameter of the aforementioned shell script to set a cipher:
```
-Dapiml.security.ciphers=<cipher-list>
```
On localhost, the default configuration can be overridden in [config/local/gateway-service.yml](/config/local/gateway-service.yml) (including other YAML files for development purposes).

The following list shows default ciphers. The API ML services use the following cipher order:
```
   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
   TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
```
Only IANA ciphers names are supported. For more information, see [Cipher Suites](https://wiki.mozilla.org/Security/Server_Side_TLS#Cipher_suites) or [List of Ciphers](https://testssl.net/openssl-iana.mapping.html).