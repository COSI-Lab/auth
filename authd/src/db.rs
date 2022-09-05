use crate::types::{Group, Passwd, Shadow};

pub trait DBContext {
    fn get_all_groups() -> Vec<Group>;
    fn get_group_by_name(name: String) -> Group;
    fn get_group_by_gid(gid: u32) -> Group;

    fn get_all_passwd() -> Vec<Passwd>;
    fn get_passwd_by_name(name: String) -> Passwd;
    fn get_passwd_by_uid(uid: u32) -> Passwd;

    fn get_all_shadow() -> Vec<Shadow>;
    fn get_shadow_by_name(name: String) -> Shadow;
}
