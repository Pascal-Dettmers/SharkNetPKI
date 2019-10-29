# SharkNetPKI
PKI lib for SharkNet app

# Setup

add mavenLocal() to your Top-level build file (project gradle) like this:

allprojects {
    repositories {
        google()
        jcenter()
        mavenLocal()
    }
}

in your lib do maven install, and refer in your app gradle to your repository directory like this:

implementation 'your-groupId:your-artifactId:your-jar-version'

