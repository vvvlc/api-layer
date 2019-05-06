## Setting Ciphers for API ML Services

You can set ciphers that are supported by the HTTPS servers in API ML services by configuring properies of the gateway, discovery service, and API catalog. Issue the following command to set a cipher:

    -Dapiml.security.ciphers=<cipher-list>

The `application.yml` file contains default value, and can be found [here](/gateway-service/src/main/resources/application.yml). You can see the default configuration in output JAR files. 

On z/OS, this can be overridden in `$ZOWE_ROOT_DIR/api-mediation/scripts/api-mediation-start-*.sh` where `*` expands to `gateway`, `catalog`, and `discovery`.
<!-- What does "this" mean? YAML? JAR? Parameters? what was being referenced? -->

On localhost, the default configuration can be overridden in [config/local/gateway-service.yml](/config/local/gateway-service.yml), and other YAML files for development purposes without rebuilding the JAR files.

The following list shows default ciphers:

    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
<!-- Do we need to show this list? or maybe we can just leave a link with the Mozilla table? -->
The IANA ciphers names are supported. 
<!-- Does this need to be mentioned, or is it self-evident? -->
The names of ciphers are available at https://wiki.mozilla.org/Security/Server_Side_TLS#Cipher_suites or https://testssl.net/openssl-iana.mapping.html.