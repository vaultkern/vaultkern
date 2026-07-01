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
const AUTH_DATA_FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const AUTH_DATA_FLAG_BACKUP_STATE: u8 = 0x10;
const AUTH_DATA_FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

pub struct PasskeyAssertionRequest<'a> {
    pub relying_party: &'a str,
    pub origin: &'a str,
    pub credential_id: Option<&'a str>,
    pub user_presence_verified: bool,
    pub related_origin_verified: bool,
    pub client_data_json_base64url: &'a str,
}

pub struct PasskeyRegistrationRequest<'a> {
    pub relying_party: &'a str,
    pub origin: &'a str,
    pub user_name: &'a str,
    pub user_handle_base64url: &'a str,
    pub related_origin_verified: bool,
    pub client_data_json_base64url: &'a str,
}

pub struct PasskeyRegistration {
    pub passkey: PasskeyRecord,
    pub dto: PasskeyRegistrationDto,
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
    if !request.user_presence_verified {
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
    validate_client_data(&client_data_json, request.origin)?;

    let authenticator_data = authenticator_data(request.relying_party, passkey);
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
        user_handle_base64url: passkey.user_handle.clone(),
        backup_eligible: passkey.backup_eligible,
        backup_state: passkey.backup_state,
    })
}

pub fn create_registration(request: PasskeyRegistrationRequest<'_>) -> Result<PasskeyRegistration> {
    validate_origin_for_relying_party(
        request.origin,
        request.relying_party,
        request.related_origin_verified,
    )?;

    let client_data_json = URL_SAFE_NO_PAD
        .decode(request.client_data_json_base64url)
        .context("invalid passkey clientDataJSON base64url")?;
    validate_client_data_type(&client_data_json, request.origin, "webauthn.create")?;

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
    let credential_id = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
    let credential_id_bytes = URL_SAFE_NO_PAD
        .decode(&credential_id)
        .context("generated passkey credential id was not base64url")?;
    let authenticator_data = attested_authenticator_data(
        request.relying_party,
        &credential_id_bytes,
        &public_key_cose,
    );
    let attestation_object = attestation_object(&authenticator_data);

    let passkey = PasskeyRecord {
        username: request.user_name.to_owned(),
        credential_id: credential_id.clone(),
        generated_user_id: None,
        private_key_pem,
        relying_party: request.relying_party.to_owned(),
        user_handle: Some(request.user_handle_base64url.to_owned()),
        backup_eligible: false,
        backup_state: false,
    };

    Ok(PasskeyRegistration {
        passkey,
        dto: PasskeyRegistrationDto {
            entry_id: String::new(),
            credential_id,
            authenticator_data_base64url: URL_SAFE_NO_PAD.encode(authenticator_data),
            attestation_object_base64url: URL_SAFE_NO_PAD.encode(attestation_object),
            client_data_json_base64url: request.client_data_json_base64url.to_owned(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key_der.as_bytes()),
            public_key_algorithm: ES256_COSE_ALGORITHM,
            user_handle_base64url: request.user_handle_base64url.to_owned(),
        },
    })
}

fn authenticator_data(relying_party: &str, passkey: &PasskeyRecord) -> Vec<u8> {
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&Sha256::digest(relying_party.as_bytes()));
    data.push(assertion_flags(passkey));
    data.extend_from_slice(&0_u32.to_be_bytes());
    data
}

fn assertion_flags(passkey: &PasskeyRecord) -> u8 {
    let backup_eligible = if passkey.backup_eligible {
        AUTH_DATA_FLAG_BACKUP_ELIGIBLE
    } else {
        0
    };
    let backup_state = if passkey.backup_state {
        AUTH_DATA_FLAG_BACKUP_STATE
    } else {
        0
    };
    AUTH_DATA_FLAG_USER_PRESENT | backup_eligible | backup_state
}

fn validate_origin_for_relying_party(
    origin: &str,
    relying_party: &str,
    related_origin_verified: bool,
) -> Result<()> {
    let parsed = Url::parse(origin).context("invalid passkey origin")?;
    let host = normalize_host(
        parsed
            .host_str()
            .context("passkey origin is missing a host")?,
    );
    let relying_party = normalize_host(relying_party);
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_loopback_host(&host)) {
        anyhow::bail!("passkey origin must use https");
    }

    if origin_host_matches_relying_party(&host, &relying_party) {
        return Ok(());
    }

    if related_origin_verified && can_accept_verified_related_origin(&host, &relying_party) {
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
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn validate_client_data(client_data_json: &[u8], origin: &str) -> Result<()> {
    validate_client_data_type(client_data_json, origin, "webauthn.get")
}

fn validate_client_data_type(
    client_data_json: &[u8],
    origin: &str,
    expected_type: &str,
) -> Result<()> {
    let value: Value =
        serde_json::from_slice(client_data_json).context("invalid passkey clientDataJSON")?;
    if value.get("type").and_then(Value::as_str) != Some(expected_type) {
        anyhow::bail!("passkey clientDataJSON type must be {expected_type}");
    }
    if value.get("origin").and_then(Value::as_str) != Some(origin) {
        anyhow::bail!("passkey clientDataJSON origin mismatch");
    }
    Ok(())
}

fn attested_authenticator_data(
    relying_party: &str,
    credential_id: &[u8],
    public_key_cose: &[u8],
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(relying_party.as_bytes()));
    auth_data.push(AUTH_DATA_FLAG_USER_PRESENT | AUTH_DATA_FLAG_ATTESTED_CREDENTIAL_DATA);
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
    use super::{PasskeyRegistrationRequest, create_registration};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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
            related_origin_verified: false,
            client_data_json_base64url: &client_data_json,
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
    fn registration_accepts_verified_related_origin() {
        let client_data_json = URL_SAFE_NO_PAD.encode(
            br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTE","origin":"https://example.co.uk","crossOrigin":false}"#,
        );

        let registration = create_registration(PasskeyRegistrationRequest {
            relying_party: "example.com",
            origin: "https://example.co.uk",
            user_name: "alice@example.com",
            user_handle_base64url: "dXNlci0x",
            related_origin_verified: true,
            client_data_json_base64url: &client_data_json,
        })
        .expect("verified related origins are allowed");

        assert_eq!(registration.passkey.relying_party, "example.com");
    }
}
