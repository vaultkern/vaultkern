package org.vaultkern.android.security

enum class UnlockEnrollmentState {
    ENROLLED,
    NOT_ENROLLED,
    INVALIDATED,
}

enum class UnlockKeySecurityLevel {
    STRONGBOX,
    TRUSTED_ENVIRONMENT,
    SOFTWARE,
    UNKNOWN,
    ;

    val isHardwareBacked: Boolean
        get() = this == STRONGBOX || this == TRUSTED_ENVIRONMENT
}
