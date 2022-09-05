use std::sync::Arc;

use actix_web::{
    get, put,
    web::{self, put},
    App, HttpResponse, HttpServer, Resource, Responder, Route,
};
use authd::db::DBContext;

#[get("/users")]
async fn users(dbx: web::Data<Arc<dyn DBContext + Send + Sync>>) -> HttpResponse {
    match dbx.get_all_passwd() {
        Ok(passwds) => HttpResponse::Ok().json(passwds),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[get("/user/by-id/{uid}")]
async fn user_by_id(
    dbx: web::Data<Arc<dyn DBContext + Send + Sync>>,
    uid: web::Path<u32>,
) -> HttpResponse {
    match dbx.get_passwd_by_uid(uid.into_inner()) {
        Ok(passwd) => HttpResponse::Ok().json(passwd),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[get("/user/by-name/{name}")]
async fn user_by_name(
    dbx: web::Data<Arc<dyn DBContext + Send + Sync>>,
    name: web::Path<String>,
) -> HttpResponse {
    match dbx.get_passwd_by_name(name.into_inner()) {
        Ok(passwd) => HttpResponse::Ok().json(passwd),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[get("/groups")]
async fn groups(dbx: web::Data<Arc<dyn DBContext + Send + Sync>>) -> HttpResponse {
    match dbx.get_all_groups() {
        Ok(groups) => HttpResponse::Ok().json(groups),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[get("/group/by-id/{uid}")]
async fn group_by_id(
    dbx: web::Data<Arc<dyn DBContext + Send + Sync>>,
    uid: web::Path<u32>,
) -> HttpResponse {
    match dbx.get_group_by_gid(uid.into_inner()) {
        Ok(group) => HttpResponse::Ok().json(group),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[get("/group/by-name/{name}")]
async fn group_by_name(
    dbx: web::Data<Arc<dyn DBContext + Send + Sync>>,
    name: web::Path<String>,
) -> HttpResponse {
    match dbx.get_group_by_name(name.into_inner()) {
        Ok(group) => HttpResponse::Ok().json(group),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

struct FauxDb;
impl DBContext for FauxDb {
    fn get_all_groups(&self) -> authd::db::Result<Vec<authd::types::Group>> {
        todo!()
    }

    fn get_group_by_name(&self, name: String) -> authd::db::Result<Option<authd::types::Group>> {
        todo!()
    }

    fn get_group_by_gid(&self, gid: u32) -> authd::db::Result<Option<authd::types::Group>> {
        todo!()
    }

    fn get_all_passwd(&self) -> authd::db::Result<Vec<authd::types::Passwd>> {
        todo!()
    }

    fn get_passwd_by_name(&self, name: String) -> authd::db::Result<Option<authd::types::Passwd>> {
        todo!()
    }

    fn get_passwd_by_uid(&self, uid: u32) -> authd::db::Result<Option<authd::types::Passwd>> {
        todo!()
    }

    fn get_all_shadow(&self) -> authd::db::Result<Vec<authd::types::Shadow>> {
        todo!()
    }

    fn get_shadow_by_name(&self, name: String) -> authd::db::Result<Option<authd::types::Shadow>> {
        todo!()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let dbx: Arc<dyn DBContext + Sync + Send> = Arc::new(FauxDb);
    HttpServer::new(move || {
        App::new()
            .service(users)
            .service(user_by_id)
            .service(user_by_name)
            .service(groups)
            .service(group_by_id)
            .service(group_by_name)
            .app_data(web::Data::new(dbx.clone()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
