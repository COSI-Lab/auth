use crate::types::{Group, Passwd, Shadow};
use std::io::{BufRead, BufReader};
use std::time::SystemTime;
use std::{fs::File, path::PathBuf};

/// Use database backed by 3 files using the `/etc/passwd` `/etc/group` and `/etc/shadow` file
/// formats.
///
/// man passwd(5)
/// man group(5)
/// man shadow(5)
pub struct Files {
    pub passwd: Reloadable<Passwd>,
    pub group: Reloadable<Group>,
    pub shadow: Reloadable<Shadow>,
}

pub struct Reloadable<T> {
    pub latest_ts: Option<SystemTime>,
    pub pth: PathBuf,
    pub data: Vec<T>,
}

impl<T> Reloadable<T> {
    fn new(pth: PathBuf) -> Self {
        Self {
            latest_ts: None,
            pth: pth,
            data: vec![],
        }
    }
    fn needs_reload(&mut self) -> anyhow::Result<bool> {
        let st = std::fs::metadata(&self.pth)?;
        if Some(st.modified()?) > self.latest_ts {
            self.latest_ts = Some(st.modified()?);
            return Ok(true);
        }
        Ok(false)
    }
}

impl Files {
    pub fn new<P1, P2, P3>(passwd: P1, group: P2, shadow: P3) -> Self
    where
        P1: Into<PathBuf>,
        P2: Into<PathBuf>,
        P3: Into<PathBuf>,
    {
        Self {
            passwd: Reloadable::new(passwd.into()),
            group: Reloadable::new(group.into()),
            shadow: Reloadable::new(shadow.into()),
        }
    }

    pub fn get_all_groups(&self) -> anyhow::Result<Vec<Group>> {
        let lines = BufReader::new(File::open(&self.group.pth)?).lines();

        let mut groups = vec![];
        for line in lines {
            let line = line?;
            // requires 4 inputs
            let mut split = line.split(':');

            let name = split.next().unwrap().to_owned();
            split.next(); // ignore password
            let gid = split.next().map(|i| i.parse::<u32>().unwrap()).unwrap();
            let members = split
                .next()
                .unwrap()
                .split(',')
                .map(ToOwned::to_owned)
                .collect();

            groups.push(Group { name, gid, members })
        }

        Ok(groups)
    }

    pub fn get_all_passwd(&self) -> anyhow::Result<Vec<Passwd>> {
        // each passwd is seperated by lines
        let lines = BufReader::new(File::open(&self.passwd.pth)?).lines();

        let mut passwd = vec![];
        for line in lines {
            let line = line?;
            let mut split = line.split(':');
            // requires 7 inputs
            let name = split.next().unwrap().to_owned();
            split.next(); // ignore password
            let id = split.next().map(|i| i.parse::<u32>().unwrap()).unwrap();
            split.next(); // ignore gid
            let gecos = split.next().unwrap().to_owned();
            let dir = split.next().unwrap().to_owned();
            let shell = split.next().unwrap().to_owned();

            passwd.push(Passwd {
                name,
                id,
                gecos,
                dir,
                shell,
            });
        }

        Ok(passwd)
    }

    pub fn get_all_shadow(&self) -> anyhow::Result<Vec<Shadow>> {
        // each passwd is seperated by lines
        let lines = BufReader::new(File::open(&self.shadow.pth)?).lines();

        let mut shadow = vec![];
        for line in lines {
            let line = line?;
            let mut split = line.split(':');
            // requires 9 inputs
            let name = split.next().unwrap().to_owned();
            let passwd = split.next().unwrap().to_owned();
            let last_change = split.next().map(|i| i.parse::<i64>().unwrap()).unwrap();
            let change_min_days = split.next().map(|i| i.parse::<i64>().unwrap()).unwrap();
            let change_max_days = split.next().map(|i| i.parse::<i64>().unwrap()).unwrap();
            let change_warn_days = split.next().map(|i| i.parse::<i64>().unwrap()).unwrap();
            let change_inactive_days = split.next().map(|i| i.parse::<i64>().unwrap()).unwrap();
            let expire_date = split.next().map(|i| i.parse::<i64>().unwrap()).unwrap();
            let _unused = split.next().map(|i| i.parse::<i64>().unwrap()).unwrap();

            shadow.push(Shadow {
                name,
                passwd,
                last_change,
                change_min_days,
                change_max_days,
                change_warn_days,
                change_inactive_days,
                expire_date,
            })
        }

        Ok(shadow)
    }

    pub fn refresh(&mut self) -> anyhow::Result<()> {
        if self.passwd.needs_reload()? {
            self.passwd.data = self.get_all_passwd()?;
        }
        if self.group.needs_reload()? {
            self.group.data = self.get_all_groups()?;
        }
        if self.shadow.needs_reload()? {
            self.shadow.data = self.get_all_shadow()?;
        }

        Ok(())
    }
}
