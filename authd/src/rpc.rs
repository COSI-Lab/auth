
use crate::types::{Group, Passwd, Shadow};


#[tarpc::service]
pub trait Authd {
    async fn get_all_groups() -> Vec<Group>;
    async fn get_group_by_name(name: String) -> Option<Group>;
    async fn get_group_by_gid(gid: u32) -> Option<Group>;

    async fn get_all_passwd() -> Vec<Passwd>;
    async fn get_passwd_by_name(name: String) -> Option<Passwd>;
    async fn get_passwd_by_uid(uid: u32) -> Option<Passwd>;

    async fn get_all_shadow() -> Vec<Shadow>;
    async fn get_shadow_by_name(name: String) -> Option<Shadow>;
}
