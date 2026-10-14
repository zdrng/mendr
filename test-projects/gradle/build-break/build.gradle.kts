plugins {
    java
}

repositories {
    mavenCentral()
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation("com.google.guava:guava:19.0")
}
