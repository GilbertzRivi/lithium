use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;

use crate::error::{LithiumError, Result};
use crate::opaque::suite::{
    ClientLoginState, ClientRegistrationState, LithiumCipherSuite, opaque_ksf,
};
use crate::secrets::{Byte64, SecretString};

fn identifiers<'a>(handler: &'a [u8], server_id: &'a [u8]) -> Identifiers<'a> {
    Identifiers {
        client: Some(handler),
        server: Some(server_id),
    }
}

pub fn client_registration_start(
    password: &SecretString,
) -> Result<(Vec<u8>, ClientRegistrationState)> {
    let mut rng = OsRng;
    let res =
        ClientRegistration::<LithiumCipherSuite>::start(&mut rng, password.expose().as_bytes())
            .map_err(|_| LithiumError::internal())?;
    Ok((res.message.serialize().to_vec(), res.state))
}

pub fn client_registration_finish(
    state: ClientRegistrationState,
    response_bytes: &[u8],
    password: &SecretString,
    handler: &[u8],
    server_id: &[u8],
) -> Result<(Vec<u8>, Byte64)> {
    let response = RegistrationResponse::<LithiumCipherSuite>::deserialize(response_bytes)
        .map_err(|_| LithiumError::invalid_credentials("bad_opaque_message"))?;
    let ksf = opaque_ksf()?;
    let mut rng = OsRng;
    let res = state
        .finish(
            &mut rng,
            password.expose().as_bytes(),
            response,
            ClientRegistrationFinishParameters::new(identifiers(handler, server_id), Some(&ksf)),
        )
        .map_err(|_| LithiumError::internal())?;
    let export_key = Byte64::from_slice(&res.export_key)?;
    Ok((res.message.serialize().to_vec(), export_key))
}

pub fn client_login_start(password: &SecretString) -> Result<(Vec<u8>, ClientLoginState)> {
    let mut rng = OsRng;
    let res = ClientLogin::<LithiumCipherSuite>::start(&mut rng, password.expose().as_bytes())
        .map_err(|_| LithiumError::internal())?;
    Ok((res.message.serialize().to_vec(), res.state))
}

pub fn client_login_finish(
    state: ClientLoginState,
    response_bytes: &[u8],
    password: &SecretString,
    handler: &[u8],
    server_id: &[u8],
) -> Result<(Vec<u8>, Byte64)> {
    let response = CredentialResponse::<LithiumCipherSuite>::deserialize(response_bytes)
        .map_err(|_| LithiumError::invalid_credentials("bad_opaque_message"))?;
    let ksf = opaque_ksf()?;
    let mut rng = OsRng;
    let res = state
        .finish(
            &mut rng,
            password.expose().as_bytes(),
            response,
            ClientLoginFinishParameters::new(None, identifiers(handler, server_id), Some(&ksf)),
        )
        .map_err(|_| LithiumError::invalid_credentials("opaque_login_failed"))?;
    let export_key = Byte64::from_slice(&res.export_key)?;
    Ok((res.message.serialize().to_vec(), export_key))
}
