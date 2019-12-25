package main.de.htw.berlin.s0551733.sharknetpki.impl;

import main.de.htw.berlin.s0551733.sharknetpki.interfaces.SharknetPublicKey;
import main.de.htw.berlin.s0551733.sharknetpki.interfaces.User;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;
import java.util.Objects;

public class SharknetPublicKeyImpl implements Serializable, SharknetPublicKey {

    private User keyOwner;
    private PublicKey publicKey;
    private Date expirationDate;

    public SharknetPublicKeyImpl(User keyOwner, PublicKey publicKey, Date expirationDate) {
        this.keyOwner = keyOwner;
        this.publicKey = publicKey;
        this.expirationDate = expirationDate;
    }

    @Override
    public User getOwner() {
        return keyOwner;
    }

    @Override
    public void setAlias(String newAlias) {
        this.keyOwner.setAlias(newAlias);

    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Date getExpirationDate() {
        return this.expirationDate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SharknetPublicKeyImpl that = (SharknetPublicKeyImpl) o;
        return Objects.equals(this.keyOwner.getUuid(), that.keyOwner.getUuid());
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyOwner.getUuid());
    }
}
