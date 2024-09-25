mod gree;
use crate::gree::*;

use askama::Template;
use axum::{
    extract::Form,
    routing::{get, post},
    response::{Html, IntoResponse, Response},
    http::StatusCode,
    Json, Router,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;


fn foo() {
    let found_devices: Vec<ScanResult> = search_devices().iter().map(|d| 
        ScanResult {
            key: bind_device(d),
            ..d.clone()
        }
    ).collect();

    for res in &found_devices {
        println!("ScanResult: address0={}, cid={}, name={}", res.ip, res.cid, res.name);
    }

    // dbg!(found_devices);
    println!("{:#?}", get_param(&found_devices[0].cid, &found_devices[0].ip, &found_devices[0].key, vec!["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet",
           "Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt"]));
    // println!("{:#?}", set_param(&found_devices[0].cid, &found_devices[0].ip, &found_devices[0].key, HashMap::from([("Pow", "0")])));
    // println!("{}", decrypt_generic("LP24Ek0OaYogxs3iQLjL4BFC4yzV+UiNP0TAe1KFsb2Ma9lM2RqI/KytvJ32IsGSZXrOr+MakVzzXHbghPeyijnWMzaLQaaw1aFXlE9k71L0cMm8bsr/y4FkxumpRg1tKs/34xhBuMSxXfNfvEgS5z7rakK3PJtxSrYtgJmzMuJzMQoS41XpnORSG7+GfavhnKYbt0iIDsdp8/ftXlA9HnnlPhlx3VxUy9nj7PufhhG80gq9HxK8Loa8WXVjgZcP4Vf5MjKxa60Xt5J1oI+ls6fK4Dsqqegc+GR44GNyUswYDpwowfxKhxJJ4skT3dYazTozQv09+BUS8d4lf3A7XpJCtl/XLH02/bjKsArYsp0="));
}

fn find_and_bind() -> Vec<ScanResult> {
    let names: HashMap<String, String> = HashMap::from([
        ("1e8ee551".to_string(), "Kitchen".to_string()),
        ("1e8fcf44".to_string(), "Hall".to_string()),
        ("1e8ee7ea".to_string(), "Cabinet".to_string()),
    ]);

    let mut found = search_devices();
    found.sort_by(|a, b| b.name.cmp(&a.name));
    
    found.iter().map(|d| 
        ScanResult {
            key: bind_device(d),
            name: names.get(&d.name).unwrap_or(&"none".to_string()).clone(),
            ..d.clone()
        }
    ).collect()
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::registry()
    .with(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
    )
    .with(tracing_subscriber::fmt::layer())
    .init();

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route("/on", post(on))
        .route("/off", post(off));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
async fn root() -> impl IntoResponse {
    let template = HelloTemplate { devices: find_and_bind() };
    HtmlTemplate(template)
}

async fn on(Form(input): Form<Input>) {
    set_param(&input.cid, &input.ip, &input.key.as_bytes().to_vec(), HashMap::from([("Pow", "1")]))
}

async fn off(Form(input): Form<Input>) {
    set_param(&input.cid, &input.ip, &input.key.as_bytes().to_vec(), HashMap::from([("Pow", "0")]))
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    ip: String,
    cid: String,
    key: String
}

#[derive(Template)]
#[template(path = "hello.html")]
struct HelloTemplate {
    devices: Vec<ScanResult>,
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {err}"),
            )
                .into_response(),
        }
    }
}
