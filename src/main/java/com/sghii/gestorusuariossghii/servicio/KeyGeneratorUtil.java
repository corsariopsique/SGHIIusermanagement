package com.sghii.gestorusuariossghii.servicio;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class KeyGeneratorUtil {

    public KeyGeneratorUtil() {
    }

    public String getKeyEncoded () throws Exception {
        // Generar una llave de 256 bits
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Codificar la llave en Base64 para almacenamiento
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        // Imprimir la llave codificada
        return encodedKey;
    }
}

