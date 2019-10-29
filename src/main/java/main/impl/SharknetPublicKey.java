package main.impl;

import main.interfaces.SharknetPublicKeyInterface;

import java.io.Serializable;
import java.security.PublicKey;

public class SharknetPublicKey implements Serializable, Comparable<SharknetPublicKeyInterface>, SharknetPublicKeyInterface {

    private String alias;
    private String uuid;
    private PublicKey publicKey;

    public SharknetPublicKey(String alias, String uuid) {
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

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public int compareTo(SharknetPublicKeyInterface o) {
        return this.uuid.compareTo(o.getUuid());
    }

    @Override
    public boolean equals(Object obj) {
        boolean result = false;

        if (obj instanceof SharknetPublicKeyInterface) {
            SharknetPublicKeyInterface key = (SharknetPublicKeyInterface) obj;
            result = key.getUuid().equals(this.uuid);
        }
        return result;
    }
}
