package main.de.htw.berlin.s0551733.sharknetpki.impl;

import main.de.htw.berlin.s0551733.sharknetpki.SharknetPublicKey;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Objects;

public class SharknetPublicKeyImpl implements Serializable, SharknetPublicKey {

    private String alias;
    private final String uuid;
    private PublicKey publicKey;

    public SharknetPublicKeyImpl(String alias, String uuid) {
        this.alias = alias;
        this.uuid = uuid;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getUuid() {
        return uuid;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SharknetPublicKeyImpl that = (SharknetPublicKeyImpl) o;
        return Objects.equals(uuid, that.uuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uuid);
    }
}
