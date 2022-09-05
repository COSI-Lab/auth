use crate::types::{Group, Passwd, Shadow};

pub trait DBContext {
    fn get_all_groups() -> Vec<Group>;
    fn get_group_by_name(name: String) -> Option<Group>;
    fn get_group_by_gid(gid: u32) -> Option<Group>;

    fn get_all_passwd() -> Vec<Passwd>;
    fn get_passwd_by_name(name: String) -> Option<Passwd>;
    fn get_passwd_by_uid(uid: u32) -> Option<Passwd>;

    fn get_all_shadow() -> Vec<Shadow>;
    fn get_shadow_by_name(name: String) -> Option<Shadow>;
}
