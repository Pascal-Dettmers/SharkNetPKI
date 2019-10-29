package main.impl;

import main.interfaces.UserInterface;

import java.io.Serializable;

public class User implements UserInterface, Serializable, Comparable<User> {

    private String uuid;
    private String alias;

    public User(String uuid, String alias) {
        this.uuid = uuid;
        this.alias = alias;
    }

    @Override
    public String getUuid() {
        return null;
    }

    @Override
    public String getAlias() {
        return null;
    }

    @Override
    public int compareTo(User o) {
        return this.uuid.compareTo(o.getUuid());
    }

    @Override
    public boolean equals(Object obj) {
        boolean result = false;

        if (obj instanceof User) {
            User user = (User) obj;
            result = user.getUuid().equals(this.uuid);
        }
        return result;
    }
}
