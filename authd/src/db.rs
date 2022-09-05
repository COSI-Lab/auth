use crate::types::{Group, Passwd, Shadow};

pub type DBErr = ();
pub type Result<T> = std::result::Result<T, DBErr>;

pub trait DBContext {
    fn get_all_groups(&self) -> Result<Vec<Group>>;
    fn get_group_by_name(&self,name: String) -> Result<Option<Group>>;
    fn get_group_by_gid(&self,gid: u32) -> Result<Option<Group>>;

    fn get_all_passwd(&self) -> Result<Vec<Passwd>>;
    fn get_passwd_by_name(&self,name: String) -> Result<Option<Passwd>>;
    fn get_passwd_by_uid(&self,uid: u32) -> Result<Option<Passwd>>;

    fn get_all_shadow(&self) -> Result<Vec<Shadow>>;
    fn get_shadow_by_name(&self,name: String) -> Result<Option<Shadow>>;
}
