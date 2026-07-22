plugins {
    kotlin("jvm") version "1.9.24"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.12.0")
}

sourceSets {
    main {
        kotlin.srcDirs(".", "../../bindings/kotlin")
    }
}

application {
    mainClass.set("org.vaultkern.core.smoke.VaultKernSmokeKt")
}

tasks.named<JavaExec>("run") {
    val repositoryRoot = projectDir.resolve("../../../..").canonicalFile
    val nativeDirectory = repositoryRoot.resolve("target/release")
    val fixture = repositoryRoot.resolve(
        "crates/vaultkern-kdbx/tests/fixtures/keepassxc-2.7.6-kdbx4.1.kdbx",
    )

    args(fixture.absolutePath, "vaultkern-external-fixture")
    jvmArgs("-Djna.library.path=${nativeDirectory.absolutePath}")
    environment("LD_LIBRARY_PATH", nativeDirectory.absolutePath)
    environment("DYLD_LIBRARY_PATH", nativeDirectory.absolutePath)
    environment("XDG_STATE_HOME", layout.buildDirectory.dir("state").get().asFile.absolutePath)
}
