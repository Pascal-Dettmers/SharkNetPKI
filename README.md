# SharkNetPKI
PKI lib for SharkNet app

# Setup

add mavenLocal() to your Top-level build file (project gradle) like this:

<pre><code>
allprojects {
    repositories {
        google()
        jcenter()
        mavenLocal()
    }
}
</code></pre>


in your lib do maven install, and refer in your app gradle to your repository directory like this:

<pre><code>
implementation 'your-groupId:your-artifactId:your-jar-version'
</code></pre>


