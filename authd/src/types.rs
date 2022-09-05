use serde::{Deserialize, Serialize};

pub trait ToNSS<T> {
    fn to_nss(&self) -> T;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Group {
    name: String,
    gid: u32,
    members: Vec<String>,
}

impl ToNSS<libnss::group::Group> for Group {
    fn to_nss(&self) -> libnss::group::Group {
        libnss::group::Group {
            name: self.name.clone(),
            passwd: "x".to_string(),
            gid: self.gid,
            members: self.members.clone(),
        }
    }
}

impl From<Group> for libnss::group::Group {
    fn from(g: Group) -> libnss::group::Group {
        libnss::group::Group {
            name: g.name,
            passwd: "x".to_string(),
            gid: g.gid,
            members: g.members,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Passwd {
    name: String,
    // forcing the uid to match the gid because we're pissed
    id: u32,
    gecos: String,
    // TODO: clients should be able to choose the front path of the home dir based on where NFS is
    // mounted.
    dir: String,
    // TODO: we could send shells as enums and allow clients to configure the binary locations
    shell: String,
}

impl ToNSS<libnss::passwd::Passwd> for Passwd {
    fn to_nss(&self) -> libnss::passwd::Passwd {
        libnss::passwd::Passwd {
            name: self.name.clone(),
            passwd: "x".to_string(),
            uid: self.id,
            gid: self.id,
            gecos: self.gecos.clone(),
            dir: self.dir.clone(),
            shell: self.shell.to_string(),
        }
    }
}

impl From<Passwd> for libnss::passwd::Passwd {
    fn from(p: Passwd) -> libnss::passwd::Passwd {
        libnss::passwd::Passwd {
            name: p.name,
            passwd: "x".to_string(),
            uid: p.id,
            gid: p.id,
            gecos: p.gecos,
            dir: p.dir,
            shell: p.shell,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Shadow {
    name: String,
    passwd: String,
    /// days since Jan 1st 1970
    last_change: i64,
    change_min_days: i64,
    change_max_days: i64,
    change_warn_days: i64,
    change_inactive_days: i64,
    expire_date: i64,
}

impl ToNSS<libnss::shadow::Shadow> for Shadow {
    fn to_nss(&self) -> libnss::shadow::Shadow {
        libnss::shadow::Shadow {
            name: self.name.clone(),
            passwd: self.passwd.clone(),
            last_change: self.last_change,
            change_min_days: self.change_min_days,
            change_max_days: self.change_max_days,
            change_warn_days: self.change_warn_days,
            change_inactive_days: self.change_inactive_days,
            expire_date: self.expire_date,
            reserved: 0,
        }
    }
}

impl From<Shadow> for libnss::shadow::Shadow {
    fn from(s: Shadow) -> Self {
        libnss::shadow::Shadow {
            name: s.name,
            passwd: s.passwd,
            last_change: s.last_change,
            change_min_days: s.change_min_days,
            change_max_days: s.change_max_days,
            change_warn_days: s.change_warn_days,
            change_inactive_days: s.change_inactive_days,
            expire_date: s.expire_date,
            reserved: 0,
        }
    }
}
