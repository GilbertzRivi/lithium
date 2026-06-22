use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration,
};
use rand_core::OsRng;

use crate::error::{LithiumError, Result};
use crate::labels::OPAQUE_SERVER_ID;
use crate::opaque::suite::LithiumCipherSuite;

type Setup = opaque_ke::ServerSetup<LithiumCipherSuite>;

pub struct ServerSetup(Setup);

impl ServerSetup {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self(Setup::new(&mut rng))
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Setup::deserialize(bytes)
            .map(Self)
            .map_err(|_| LithiumError::internal())
    }
}

fn identifiers(handler: &[u8]) -> Identifiers<'_> {
    Identifiers {
        client: Some(handler),
        server: Some(OPAQUE_SERVER_ID),
    }
}

fn bad_message() -> LithiumError {
    LithiumError::invalid_credentials("bad_opaque_message")
}

pub fn server_registration_start(
    setup: &ServerSetup,
    request_bytes: &[u8],
    credential_identifier: &[u8],
) -> Result<Vec<u8>> {
    let request = RegistrationRequest::<LithiumCipherSuite>::deserialize(request_bytes)
        .map_err(|_| bad_message())?;
    let res = ServerRegistration::start(&setup.0, request, credential_identifier)
        .map_err(|_| LithiumError::internal())?;
    Ok(res.message.serialize().to_vec())
}

pub fn server_registration_finish(upload_bytes: &[u8]) -> Result<Vec<u8>> {
    let upload = RegistrationUpload::<LithiumCipherSuite>::deserialize(upload_bytes)
        .map_err(|_| bad_message())?;
    Ok(ServerRegistration::finish(upload).serialize().to_vec())
}

pub fn server_login_start(
    setup: &ServerSetup,
    record_bytes: &[u8],
    request_bytes: &[u8],
    credential_identifier: &[u8],
    handler: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let record = ServerRegistration::<LithiumCipherSuite>::deserialize(record_bytes)
        .map_err(|_| LithiumError::internal())?;
    let request = CredentialRequest::<LithiumCipherSuite>::deserialize(request_bytes)
        .map_err(|_| bad_message())?;

    let params = ServerLoginParameters {
        context: None,
        identifiers: identifiers(handler),
    };

    let mut rng = OsRng;
    let res = ServerLogin::start(
        &mut rng,
        &setup.0,
        Some(record),
        request,
        credential_identifier,
        params,
    )
    .map_err(|_| LithiumError::internal())?;

    Ok((
        res.message.serialize().to_vec(),
        res.state.serialize().to_vec(),
    ))
}

pub fn server_login_finish(
    state_bytes: &[u8],
    finalization_bytes: &[u8],
    handler: &[u8],
) -> Result<()> {
    let state = ServerLogin::<LithiumCipherSuite>::deserialize(state_bytes)
        .map_err(|_| LithiumError::internal())?;
    let finalization =
        CredentialFinalization::<LithiumCipherSuite>::deserialize(finalization_bytes)
            .map_err(|_| bad_message())?;

    let params = ServerLoginParameters {
        context: None,
        identifiers: identifiers(handler),
    };

    state
        .finish(finalization, params)
        .map(|_| ())
        .map_err(|_| LithiumError::invalid_credentials("opaque_login_failed"))
}

#[cfg(feature = "fuzzing")]
pub fn opaque_parse_fuzz(data: &[u8]) {
    let _ = RegistrationRequest::<LithiumCipherSuite>::deserialize(data);
    let _ = RegistrationUpload::<LithiumCipherSuite>::deserialize(data);
    let _ = CredentialRequest::<LithiumCipherSuite>::deserialize(data);
    let _ = CredentialFinalization::<LithiumCipherSuite>::deserialize(data);
    let _ = ServerSetup::deserialize(data);
}
