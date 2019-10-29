package main.interfaces;

import java.security.PublicKey;

public interface SharknetPublicKeyInterface {

    String getAlias();
    String getUuid();
    PublicKey getPublicKey();
    boolean equals(Object obj);
}
