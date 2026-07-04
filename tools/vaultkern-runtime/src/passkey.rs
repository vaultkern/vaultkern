use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    EncodedPoint,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::rand_core::OsRng,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use vaultkern_core::PasskeyRecord;
use vaultkern_runtime_protocol::PasskeyAssertionDto;
use vaultkern_runtime_protocol::PasskeyRegistrationDto;

const ES256_COSE_ALGORITHM: i32 = -7;
const AUTH_DATA_FLAG_USER_PRESENT: u8 = 0x01;
const AUTH_DATA_FLAG_USER_VERIFIED: u8 = 0x04;
const AUTH_DATA_FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const AUTH_DATA_FLAG_BACKUP_STATE: u8 = 0x10;
const AUTH_DATA_FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

pub struct PasskeyAssertionRequest<'a> {
    pub relying_party: &'a str,
    pub origin: &'a str,
    pub credential_id: Option<&'a str>,
    pub discoverable: bool,
    pub user_presence_verified: bool,
    pub user_verified: bool,
    pub related_origin_verified: bool,
    pub client_data_json_base64url: &'a str,
    pub challenge_base64url: &'a str,
    pub top_origin: Option<&'a str>,
    pub ancestor_origins: &'a [String],
}

pub struct PasskeyRegistrationRequest<'a> {
    pub relying_party: &'a str,
    pub origin: &'a str,
    pub user_name: &'a str,
    pub user_handle_base64url: &'a str,
    pub public_key_algorithm: i32,
    pub user_verified: bool,
    pub related_origin_verified: bool,
    pub client_data_json_base64url: &'a str,
    pub challenge_base64url: &'a str,
    pub top_origin: Option<&'a str>,
    pub ancestor_origins: &'a [String],
}

pub struct PasskeyRegistration {
    pub passkey: PasskeyRecord,
    pub dto: PasskeyRegistrationDto,
}

pub fn generate_passkey_credential_id() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

pub fn create_assertion(
    passkey: &PasskeyRecord,
    request: PasskeyAssertionRequest<'_>,
) -> Result<PasskeyAssertionDto> {
    if request
        .credential_id
        .is_some_and(|credential_id| passkey.credential_id != credential_id)
    {
        anyhow::bail!("passkey credential id mismatch");
    }
    if passkey.relying_party != request.relying_party {
        anyhow::bail!("passkey relying party mismatch");
    }
    if !request.user_presence_verified && !request.user_verified {
        anyhow::bail!("passkey user presence was not verified");
    }
    validate_origin_for_relying_party(
        request.origin,
        request.relying_party,
        request.related_origin_verified,
    )?;

    let client_data_json = URL_SAFE_NO_PAD
        .decode(request.client_data_json_base64url)
        .context("invalid passkey clientDataJSON base64url")?;
    validate_client_data(
        &client_data_json,
        request.origin,
        request.challenge_base64url,
        request.top_origin,
        request.ancestor_origins,
    )?;

    let authenticator_data =
        authenticator_data(request.relying_party, passkey, request.user_verified);
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_payload = authenticator_data.clone();
    signed_payload.extend_from_slice(&client_data_hash);

    let signing_key = SigningKey::from_pkcs8_pem(&passkey.private_key_pem)
        .context("invalid passkey private key")?;
    let signature: Signature = signing_key.sign(&signed_payload);
    let signature_der = signature.to_der();

    Ok(PasskeyAssertionDto {
        credential_id: passkey.credential_id.clone(),
        authenticator_data_base64url: URL_SAFE_NO_PAD.encode(authenticator_data),
        client_data_json_base64url: request.client_data_json_base64url.to_owned(),
        signature_base64url: URL_SAFE_NO_PAD.encode(signature_der.as_bytes()),
        user_handle_base64url: if request.discoverable {
            passkey.user_handle.clone()
        } else {
            None
        },
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    })
}

#[cfg(test)]
pub fn create_registration(request: PasskeyRegistrationRequest<'_>) -> Result<PasskeyRegistration> {
    create_registration_with_credential_id(request, generate_passkey_credential_id())
}

pub fn create_registration_with_credential_id(
    request: PasskeyRegistrationRequest<'_>,
    credential_id: String,
) -> Result<PasskeyRegistration> {
    validate_origin_for_relying_party(
        request.origin,
        request.relying_party,
        request.related_origin_verified,
    )?;

    let client_data_json = URL_SAFE_NO_PAD
        .decode(request.client_data_json_base64url)
        .context("invalid passkey clientDataJSON base64url")?;
    validate_client_data_type(
        &client_data_json,
        request.origin,
        "webauthn.create",
        request.challenge_base64url,
        request.top_origin,
        request.ancestor_origins,
    )?;
    validate_public_key_algorithm(request.public_key_algorithm)?;
    validate_user_handle(request.user_handle_base64url)?;

    let signing_key = SigningKey::random(&mut OsRng);
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode passkey private key")?
        .to_string();
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    let public_key_der = verifying_key
        .to_public_key_der()
        .context("failed to encode passkey public key")?;
    let public_key_cose = cose_es256_public_key(&public_key)?;
    let credential_id_bytes = URL_SAFE_NO_PAD
        .decode(&credential_id)
        .context("generated passkey credential id was not base64url")?;
    let authenticator_data = attested_authenticator_data(
        request.relying_party,
        &credential_id_bytes,
        &public_key_cose,
        request.user_verified,
    );
    let attestation_object = attestation_object(&authenticator_data);

    let passkey = PasskeyRecord {
        username: request.user_name.to_owned(),
        credential_id: credential_id.clone(),
        generated_user_id: None,
        private_key_pem,
        relying_party: request.relying_party.to_owned(),
        user_handle: Some(request.user_handle_base64url.to_owned()),
        backup_eligible: true,
        backup_state: true,
    };

    Ok(PasskeyRegistration {
        passkey,
        dto: PasskeyRegistrationDto {
            entry_id: String::new(),
            credential_id,
            created: true,
            authenticator_data_base64url: URL_SAFE_NO_PAD.encode(authenticator_data),
            attestation_object_base64url: URL_SAFE_NO_PAD.encode(attestation_object),
            client_data_json_base64url: request.client_data_json_base64url.to_owned(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key_der.as_bytes()),
            public_key_algorithm: ES256_COSE_ALGORITHM,
            user_handle_base64url: request.user_handle_base64url.to_owned(),
        },
    })
}

fn authenticator_data(
    relying_party: &str,
    passkey: &PasskeyRecord,
    user_verified: bool,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&Sha256::digest(relying_party.as_bytes()));
    data.push(assertion_flags(passkey, user_verified));
    data.extend_from_slice(&0_u32.to_be_bytes());
    data
}

fn assertion_flags(passkey: &PasskeyRecord, user_verified: bool) -> u8 {
    let backup_eligible = if passkey.backup_eligible || passkey.backup_state {
        AUTH_DATA_FLAG_BACKUP_ELIGIBLE
    } else {
        0
    };
    let backup_state = if passkey.backup_state {
        AUTH_DATA_FLAG_BACKUP_STATE
    } else {
        0
    };
    let user_verified = if user_verified {
        AUTH_DATA_FLAG_USER_VERIFIED
    } else {
        0
    };
    AUTH_DATA_FLAG_USER_PRESENT | user_verified | backup_eligible | backup_state
}

fn validate_origin_for_relying_party(
    origin: &str,
    relying_party: &str,
    related_origin_verified: bool,
) -> Result<()> {
    if origin.trim() != origin {
        anyhow::bail!("invalid passkey origin");
    }
    if relying_party.trim().is_empty() || relying_party.trim() != relying_party {
        anyhow::bail!("invalid passkey relying party");
    }
    let canonical_relying_party = normalize_host(relying_party);
    if relying_party != canonical_relying_party {
        anyhow::bail!("invalid passkey relying party");
    }
    let parsed = Url::parse(origin).context("invalid passkey origin")?;
    let host = normalize_host(
        parsed
            .host_str()
            .context("passkey origin is missing a host")?,
    );
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("invalid passkey origin");
    }
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_loopback_host(&host)) {
        anyhow::bail!("passkey origin must use https");
    }

    if origin_host_matches_relying_party(&host, &canonical_relying_party) {
        return Ok(());
    }

    if related_origin_verified
        && can_accept_verified_related_origin(&host, &canonical_relying_party)
    {
        return Ok(());
    }

    anyhow::bail!("passkey origin does not match relying party")
}

fn origin_host_matches_relying_party(host: &str, relying_party: &str) -> bool {
    if is_loopback_host(host) || is_loopback_host(relying_party) {
        return host == relying_party;
    }

    if is_ip_address(host) || is_ip_address(relying_party) {
        return host == relying_party;
    }

    if psl::domain_str(relying_party).is_none() {
        return false;
    }

    host == relying_party || host.ends_with(&format!(".{relying_party}"))
}

fn can_accept_verified_related_origin(host: &str, relying_party: &str) -> bool {
    if is_loopback_host(host) || is_loopback_host(relying_party) {
        return false;
    }

    if is_ip_address(host) || is_ip_address(relying_party) {
        return false;
    }

    psl::domain_str(host).is_some() && psl::domain_str(relying_party).is_some()
}

fn normalize_host(host: &str) -> String {
    let canonical = host.trim().trim_end_matches('.').to_ascii_lowercase();
    canonical
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&canonical)
        .to_owned()
}

fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn validate_client_data(
    client_data_json: &[u8],
    origin: &str,
    challenge_base64url: &str,
    top_origin: Option<&str>,
    ancestor_origins: &[String],
) -> Result<()> {
    validate_client_data_type(
        client_data_json,
        origin,
        "webauthn.get",
        challenge_base64url,
        top_origin,
        ancestor_origins,
    )
}

fn validate_client_data_type(
    client_data_json: &[u8],
    origin: &str,
    expected_type: &str,
    challenge_base64url: &str,
    top_origin: Option<&str>,
    ancestor_origins: &[String],
) -> Result<()> {
    let value: Value =
        serde_json::from_slice(client_data_json).context("invalid passkey clientDataJSON")?;
    if value.get("type").and_then(Value::as_str) != Some(expected_type) {
        anyhow::bail!("passkey clientDataJSON type must be {expected_type}");
    }
    if value.get("origin").and_then(Value::as_str) != Some(origin) {
        anyhow::bail!("passkey clientDataJSON origin mismatch");
    }
    if value.get("challenge").and_then(Value::as_str) != Some(challenge_base64url) {
        anyhow::bail!("passkey clientDataJSON challenge mismatch");
    }
    let expected_cross_origin = top_origin
        .is_some_and(|top_origin| !origins_are_same_origin(top_origin, origin))
        || ancestor_origins
            .iter()
            .any(|ancestor_origin| !origins_are_same_origin(ancestor_origin, origin));
    if value.get("crossOrigin").and_then(Value::as_bool) != Some(expected_cross_origin) {
        anyhow::bail!("passkey clientDataJSON crossOrigin mismatch");
    }
    let client_top_origin = value.get("topOrigin").and_then(Value::as_str);
    if expected_cross_origin {
        if !matches!(
            (client_top_origin, top_origin),
            (Some(client_top_origin), Some(top_origin))
                if origins_are_same_origin(client_top_origin, top_origin)
        ) {
            anyhow::bail!("passkey clientDataJSON topOrigin mismatch");
        }
    } else if value.get("topOrigin").is_some() {
        anyhow::bail!("passkey clientDataJSON topOrigin mismatch");
    }
    Ok(())
}

fn origins_are_same_origin(left: &str, right: &str) -> bool {
    let (Some(left), Some(right)) = (origin_url(left), origin_url(right)) else {
        return false;
    };
    left.scheme() == right.scheme()
        && left.host_str().map(|host| host.to_ascii_lowercase())
            == right.host_str().map(|host| host.to_ascii_lowercase())
        && left.port_or_known_default() == right.port_or_known_default()
}

fn origin_url(value: &str) -> Option<Url> {
    let parsed = Url::parse(value).ok()?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed)
}

fn validate_user_handle(user_handle_base64url: &str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(user_handle_base64url)
        .context("invalid passkey user handle base64url")?;
    if bytes.is_empty() || bytes.len() > 64 {
        anyhow::bail!("passkey user handle must be 1 to 64 bytes");
    }
    Ok(())
}

fn validate_public_key_algorithm(public_key_algorithm: i32) -> Result<()> {
    if public_key_algorithm != ES256_COSE_ALGORITHM {
        anyhow::bail!("unsupported passkey public key algorithm");
    }
    Ok(())
}

fn attested_authenticator_data(
    relying_party: &str,
    credential_id: &[u8],
    public_key_cose: &[u8],
    user_verified: bool,
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(relying_party.as_bytes()));
    let user_verified = if user_verified {
        AUTH_DATA_FLAG_USER_VERIFIED
    } else {
        0
    };
    auth_data.push(
        AUTH_DATA_FLAG_USER_PRESENT
            | user_verified
            | AUTH_DATA_FLAG_BACKUP_ELIGIBLE
            | AUTH_DATA_FLAG_BACKUP_STATE
            | AUTH_DATA_FLAG_ATTESTED_CREDENTIAL_DATA,
    );
    auth_data.extend_from_slice(&0_u32.to_be_bytes());
    auth_data.extend_from_slice(&[0; 16]);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(public_key_cose);
    auth_data
}

fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut object = Vec::new();
    cbor_map_len(&mut object, 3);
    cbor_text(&mut object, "fmt");
    cbor_text(&mut object, "none");
    cbor_text(&mut object, "attStmt");
    cbor_map_len(&mut object, 0);
    cbor_text(&mut object, "authData");
    cbor_bytes(&mut object, &auth_data);
    object
}

fn cose_es256_public_key(point: &EncodedPoint) -> Result<Vec<u8>> {
    let x = point
        .x()
        .context("passkey public key is missing x coordinate")?;
    let y = point
        .y()
        .context("passkey public key is missing y coordinate")?;
    let mut key = Vec::new();
    cbor_map_len(&mut key, 5);
    cbor_i64(&mut key, 1);
    cbor_i64(&mut key, 2);
    cbor_i64(&mut key, 3);
    cbor_i64(&mut key, ES256_COSE_ALGORITHM.into());
    cbor_i64(&mut key, -1);
    cbor_i64(&mut key, 1);
    cbor_i64(&mut key, -2);
    cbor_bytes(&mut key, x);
    cbor_i64(&mut key, -3);
    cbor_bytes(&mut key, y);
    Ok(key)
}

fn cbor_map_len(output: &mut Vec<u8>, len: u64) {
    cbor_major(output, 5, len);
}

fn cbor_text(output: &mut Vec<u8>, value: &str) {
    cbor_major(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn cbor_bytes(output: &mut Vec<u8>, value: &[u8]) {
    cbor_major(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

fn cbor_i64(output: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        cbor_major(output, 0, value as u64);
    } else {
        cbor_major(output, 1, (-1 - value) as u64);
    }
}

fn cbor_major(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PasskeyAssertionRequest, PasskeyRegistrationRequest, create_assertion, create_registration,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use vaultkern_core::PasskeyRecord;

    #[test]
    fn registration_rejects_public_suffix_relying_party() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://attacker.com","crossOrigin":false}"#,
        );

        let error = match create_registration(PasskeyRegistrationRequest {
            relying_party: "com",
            origin: "https://attacker.com",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        }) {
            Ok(_) => panic!("public suffix RP ID must be rejected"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("passkey origin does not match relying party")
        );
    }

    #[test]
    fn registration_rejects_non_origin_origin() {
        for origin in ["https://example.com/path", " https://example.com"] {
            let client_data_json = URL_SAFE_NO_PAD.encode(
                format!(
                    r#"{{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"{origin}","crossOrigin":false}}"#
                ),
            );

            let error = match create_registration(PasskeyRegistrationRequest {
                relying_party: "example.com",
                origin,
                user_name: "alice@example.com",
                user_handle_base64url: "dXNlci0x",
                public_key_algorithm: -7,
                user_verified: false,
                related_origin_verified: false,
                client_data_json_base64url: &client_data_json,
                challenge_base64url: "Y2hhbGxlbmdlLTE",
                top_origin: None,
                ancestor_origins: &[],
            }) {
                Ok(_) => panic!("non-origin passkey origin must be rejected: {origin:?}"),
                Err(error) => error,
            };

            assert!(error.to_string().contains("invalid passkey origin"));
        }
    }

    #[test]
    fn registration_rejects_whitespace_padded_relying_party() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://login.example.com","crossOrigin":false}"#,
        );

        for relying_party in [" example.com", "Example.COM"] {
            let error = match create_registration(PasskeyRegistrationRequest {
                relying_party,
                origin: "https://login.example.com",
                user_name: "alice@example.com",
                user_handle_base64url: "dXNlci0x",
                public_key_algorithm: -7,
                user_verified: false,
                related_origin_verified: false,
                client_data_json_base64url: &client_data_json,
                challenge_base64url: "Y2hhbGxlbmdlLTE",
                top_origin: None,
                ancestor_origins: &[],
            }) {
                Ok(_) => panic!("non-canonical passkey relying party must be rejected"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains("invalid passkey relying party"),
                "unexpected error for {relying_party:?}: {error}"
            );
        }
    }

    #[test]
    fn registration_accepts_verified_related_origin() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.co.uk","crossOrigin":false}"#,
        );

        let registration = create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.co.uk",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: true,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        })
        .expect("verified related origins are allowed");

        assert_eq!(registration.passkey.relying_party, "example.com");
    }

    #[test]
    fn registration_accepts_bracketed_ipv6_loopback_origin() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"http://[::1]:8877","crossOrigin":false}"#,
        );

        let registration = create_registration(PasskeyRegistrationRequest {
            relying_party: "::1",
            origin: "http://[::1]:8877",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        })
        .expect("bracketed IPv6 loopback origin should be allowed for local smoke tests");

        assert_eq!(registration.passkey.relying_party, "::1");
    }

    #[test]
    fn registration_marks_vault_backed_passkeys_as_backed_up() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
        );

        let registration = create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.com",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        })
        .expect("registration");
        let authenticator_data = URL_SAFE_NO_PAD
            .decode(&registration.dto.authenticator_data_base64url)
            .expect("decode auth data");

        assert!(registration.passkey.backup_eligible);
        assert!(registration.passkey.backup_state);
        assert_eq!(
            authenticator_data[32],
            super::AUTH_DATA_FLAG_USER_PRESENT
                | super::AUTH_DATA_FLAG_BACKUP_ELIGIBLE
                | super::AUTH_DATA_FLAG_BACKUP_STATE
                | super::AUTH_DATA_FLAG_ATTESTED_CREDENTIAL_DATA
        );
    }

    #[test]
    fn registration_uses_none_attestation_and_zero_aaguid() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
        );

        let registration = create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.com",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        })
        .expect("registration");
        let authenticator_data = URL_SAFE_NO_PAD
            .decode(&registration.dto.authenticator_data_base64url)
            .expect("decode auth data");
        let attestation_object = URL_SAFE_NO_PAD
            .decode(&registration.dto.attestation_object_base64url)
            .expect("decode attestation object");

        assert_eq!(&authenticator_data[37..53], [0_u8; 16]);
        assert!(attestation_object.starts_with(&[
            0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x67, b'a', b't', b't',
            b'S', b't', b'm', b't', 0xa0, 0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a',
        ]));
        assert_eq!(
            auth_data_from_attestation_object(&attestation_object)
                .expect("attestation object must be valid CBOR without trailing bytes"),
            authenticator_data
        );
    }

    #[test]
    fn registration_rejects_user_handle_longer_than_64_bytes() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
        );
        let oversized_user_handle = URL_SAFE_NO_PAD.encode([7_u8; 65]);

        let error = match create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.com",
            user_name: "alice@example.com",
            user_handle_base64url: &oversized_user_handle,
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        }) {
            Ok(_) => panic!("oversized passkey user handle must be rejected"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("passkey user handle must be 1 to 64 bytes")
        );
    }

    #[test]
    fn registration_rejects_empty_user_handle() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.com","crossOrigin":false}"#,
        );

        let error = match create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.com",
            user_name: "alice@example.com",
            user_handle_base64url: "",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        }) {
            Ok(_) => panic!("empty passkey user handle must be rejected"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("passkey user handle must be 1 to 64 bytes")
        );
    }

    #[test]
    fn registration_rejects_client_data_challenge_mismatch_at_signer_boundary() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"d3JvbmctY2hhbGxlbmdl","origin":"https://example.com","crossOrigin":false}"#,
        );

        let error = match create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.com",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
            challenge_base64url: "Y2hhbGxlbmdlLTE",
            top_origin: None,
            ancestor_origins: &[],
        }) {
            Ok(_) => panic!("mismatched passkey challenge must be rejected"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("passkey clientDataJSON challenge mismatch")
        );
    }

    #[test]
    fn assertion_rejects_client_data_cross_origin_mismatch_at_signer_boundary() {
        let create_client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y3JlYXRlLWNoYWxsZW5nZQ","origin":"https://example.com","crossOrigin":false}"#,
        );
        let registration = create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.com",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &create_client_data_json,
            challenge_base64url: "Y3JlYXRlLWNoYWxsZW5nZQ",
            top_origin: None,
            ancestor_origins: &[],
        })
        .expect("registration");
        let get_client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.get","challenge":"Z2V0LWNoYWxsZW5nZQ","origin":"https://example.com","crossOrigin":false}"#,
        );

        let error = match create_assertion(
            &registration.passkey,
            PasskeyAssertionRequest {
                relying_party: "example.com",
                origin: "https://example.com",
                credential_id: Some(&registration.passkey.credential_id),
                discoverable: false,
                user_presence_verified: true,
                user_verified: false,
                related_origin_verified: false,
                client_data_json_base64url: &get_client_data_json,
                challenge_base64url: "Z2V0LWNoYWxsZW5nZQ",
                top_origin: Some("https://embedder.example.net"),
                ancestor_origins: &[],
            },
        ) {
            Ok(_) => panic!("mismatched passkey crossOrigin must be rejected"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("passkey clientDataJSON crossOrigin mismatch")
        );
    }

    #[test]
    fn assertion_flags_never_set_backup_state_without_backup_eligible() {
        let passkey = PasskeyRecord {
            username: "alice@example.com".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
            generated_user_id: None,
            private_key_pem: String::new(),
            relying_party: "example.com".into(),
            user_handle: Some("dXNlci0x".into()),
            backup_eligible: false,
            backup_state: true,
        };

        let flags = super::assertion_flags(&passkey, false);

        assert_ne!(flags & super::AUTH_DATA_FLAG_BACKUP_STATE, 0);
        assert_ne!(flags & super::AUTH_DATA_FLAG_BACKUP_ELIGIBLE, 0);
    }

    #[test]
    fn assertion_flags_do_not_set_extension_data_by_default() {
        const AUTH_DATA_FLAG_EXTENSION_DATA: u8 = 0x80;
        let passkey = PasskeyRecord {
            username: "alice@example.com".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
            generated_user_id: None,
            private_key_pem: String::new(),
            relying_party: "example.com".into(),
            user_handle: Some("dXNlci0x".into()),
            backup_eligible: true,
            backup_state: true,
        };

        let flags = super::assertion_flags(&passkey, false);

        assert_eq!(flags & AUTH_DATA_FLAG_EXTENSION_DATA, 0);
    }

    #[test]
    fn assertion_flags_do_not_set_user_verified() {
        const AUTH_DATA_FLAG_USER_VERIFIED: u8 = 0x04;
        let passkey = PasskeyRecord {
            username: "alice@example.com".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
            generated_user_id: None,
            private_key_pem: String::new(),
            relying_party: "example.com".into(),
            user_handle: Some("dXNlci0x".into()),
            backup_eligible: true,
            backup_state: true,
        };

        let flags = super::assertion_flags(&passkey, false);

        assert_eq!(flags & AUTH_DATA_FLAG_USER_VERIFIED, 0);
    }

    #[test]
    fn assertion_flags_set_user_verified_only_when_requested() {
        let passkey = PasskeyRecord {
            username: "alice@example.com".into(),
            credential_id: "Y3JlZGVudGlhbA".into(),
            generated_user_id: None,
            private_key_pem: String::new(),
            relying_party: "example.com".into(),
            user_handle: Some("dXNlci0x".into()),
            backup_eligible: true,
            backup_state: true,
        };

        let flags = super::assertion_flags(&passkey, true);

        assert_ne!(flags & super::AUTH_DATA_FLAG_USER_VERIFIED, 0);
    }

    #[test]
    fn assertion_accepts_user_verification_as_presence() {
        let create_client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y3JlYXRlLWNoYWxsZW5nZQ","origin":"https://example.com","crossOrigin":false}"#,
        );
        let registration = create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.com",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            public_key_algorithm: -7,
            user_verified: false,
            related_origin_verified: false,
            client_data_json_base64url: &create_client_data_json,
            challenge_base64url: "Y3JlYXRlLWNoYWxsZW5nZQ",
            top_origin: None,
            ancestor_origins: &[],
        })
        .expect("registration");
        let get_client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.get","challenge":"Z2V0LWNoYWxsZW5nZQ","origin":"https://example.com","crossOrigin":false}"#,
        );

        let assertion = create_assertion(
            &registration.passkey,
            PasskeyAssertionRequest {
                relying_party: "example.com",
                origin: "https://example.com",
                credential_id: Some(&registration.passkey.credential_id),
                discoverable: false,
                user_presence_verified: false,
                user_verified: true,
                related_origin_verified: false,
                client_data_json_base64url: &get_client_data_json,
                challenge_base64url: "Z2V0LWNoYWxsZW5nZQ",
                top_origin: None,
                ancestor_origins: &[],
            },
        )
        .expect("assertion");
        let authenticator_data = URL_SAFE_NO_PAD
            .decode(assertion.authenticator_data_base64url)
            .expect("authenticator data");
        let flags = authenticator_data[32];

        assert_ne!(flags & super::AUTH_DATA_FLAG_USER_PRESENT, 0);
        assert_ne!(flags & super::AUTH_DATA_FLAG_USER_VERIFIED, 0);
    }

    fn auth_data_from_attestation_object(bytes: &[u8]) -> Option<Vec<u8>> {
        let mut cursor = 0;
        if read_len(bytes, &mut cursor, 5)? != 3 {
            return None;
        }
        if !expect_text(bytes, &mut cursor, "fmt") {
            return None;
        }
        if !expect_text(bytes, &mut cursor, "none") {
            return None;
        }
        if !expect_text(bytes, &mut cursor, "attStmt") {
            return None;
        }
        if read_len(bytes, &mut cursor, 5)? != 0 {
            return None;
        }
        if !expect_text(bytes, &mut cursor, "authData") {
            return None;
        }
        let auth_data = read_bytes(bytes, &mut cursor)?.to_vec();
        if cursor != bytes.len() {
            return None;
        }
        Some(auth_data)
    }

    fn expect_text(bytes: &[u8], cursor: &mut usize, expected: &str) -> bool {
        let Some(len) = read_len(bytes, cursor, 3) else {
            return false;
        };
        let Some(value) = bytes.get(*cursor..cursor.saturating_add(len)) else {
            return false;
        };
        *cursor += len;
        value == expected.as_bytes()
    }

    fn read_bytes<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
        let len = read_len(bytes, cursor, 2)?;
        let value = bytes.get(*cursor..cursor.saturating_add(len))?;
        *cursor += len;
        Some(value)
    }

    fn read_len(bytes: &[u8], cursor: &mut usize, expected_major: u8) -> Option<usize> {
        let initial = *bytes.get(*cursor)?;
        *cursor += 1;
        if initial >> 5 != expected_major {
            return None;
        }
        match initial & 0x1f {
            value @ 0..=23 => Some(value.into()),
            24 => {
                let value = *bytes.get(*cursor)?;
                *cursor += 1;
                Some(value.into())
            }
            25 => {
                let value = u16::from_be_bytes(
                    bytes
                        .get(*cursor..cursor.saturating_add(2))?
                        .try_into()
                        .ok()?,
                );
                *cursor += 2;
                Some(value.into())
            }
            26 => {
                let value = u32::from_be_bytes(
                    bytes
                        .get(*cursor..cursor.saturating_add(4))?
                        .try_into()
                        .ok()?,
                );
                *cursor += 4;
                usize::try_from(value).ok()
            }
            _ => None,
        }
    }
}
