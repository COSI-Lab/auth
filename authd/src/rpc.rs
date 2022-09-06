use opaque_ke::{
    ciphersuite::CipherSuite, CredentialFinalization, CredentialRequest, CredentialResponse,
    RegistrationRequest, RegistrationResponse, RegistrationUpload,
};

use crate::types::{Group, Passwd, Shadow};

pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = argon2::Argon2<'static>;
}

#[tarpc::service]
pub trait Authd {
    async fn start_login(
        username: String,
        req: CredentialRequest<DefaultCipherSuite>,
    ) -> Result<CredentialResponse<DefaultCipherSuite>, String>;
    async fn finish_login(req: CredentialFinalization<DefaultCipherSuite>);

    async fn get_all_groups() -> Vec<Group>;
    async fn get_group_by_name(name: String) -> Option<Group>;
    async fn get_group_by_gid(gid: u32) -> Option<Group>;

    async fn get_all_passwd() -> Vec<Passwd>;
    async fn get_passwd_by_name(name: String) -> Option<Passwd>;
    async fn get_passwd_by_uid(uid: u32) -> Option<Passwd>;

    async fn get_all_shadow() -> Vec<Shadow>;
    async fn get_shadow_by_name(name: String) -> Option<Shadow>;

    async fn register_new_user(
        username: String,
        selected_uid: Option<u32>,
        reg: RegistrationRequest<DefaultCipherSuite>,
    ) -> RegistrationResponse<DefaultCipherSuite>;
    async fn finish_registration(reg: RegistrationUpload<DefaultCipherSuite>);
}
