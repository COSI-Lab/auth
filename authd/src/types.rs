use serde::{Deserialize, Serialize};

pub trait ToNSS {
    type Target;
    fn to_nss(&self) -> Self::Target;
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Group {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

impl ToNSS for Group {
    type Target = libnss::group::Group;
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Passwd {
    pub name: String,
    // forcing the uid to match the gid because we're pissed
    pub id: u32,
    pub gecos: String,
    // TODO: clients should be able to choose the front path of the home dir based on where NFS is
    // mounted.
    pub dir: String,
    // TODO: we could send shells as enums and allow clients to configure the binary locations
    pub shell: String,
}

impl ToNSS for Passwd {
    type Target = libnss::passwd::Passwd;
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Shadow {
    pub name: String,
    pub passwd: String,
    /// days since Jan 1st 1970
    pub last_change: i64,
    pub change_min_days: i64,
    pub change_max_days: i64,
    pub change_warn_days: i64,
    pub change_inactive_days: Option<i64>,
    pub expire_date: Option<i64>,
}

impl ToNSS for Shadow {
    type Target = libnss::shadow::Shadow;
    fn to_nss(&self) -> libnss::shadow::Shadow {
        libnss::shadow::Shadow {
            name: self.name.clone(),
            passwd: self.passwd.clone(),
            last_change: self.last_change,
            change_min_days: self.change_min_days,
            change_max_days: self.change_max_days,
            change_warn_days: self.change_warn_days,
            change_inactive_days: self.change_inactive_days.unwrap_or(0),
            expire_date: self.expire_date.unwrap_or(0),
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
            change_inactive_days: s.change_inactive_days.unwrap_or(0),
            expire_date: s.expire_date.unwrap_or(0),
            reserved: 0,
        }
    }
}
