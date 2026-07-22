plugins {
    id("com.android.application") version "8.5.2"
    id("org.jetbrains.kotlin.android") version "1.9.24"
}

repositories {
    google()
    mavenCentral()
}

android {
    namespace = "org.vaultkern.core.smoke"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.vaultkern.core.smoke"
        minSdk = 34
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    sourceSets["main"].java.srcDir("../../bindings/kotlin")
    sourceSets["androidTest"].assets.srcDir("../../../vaultkern-kdbx/tests/fixtures")
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
