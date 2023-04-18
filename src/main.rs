extern crate core;

use std::{process, str};
use std::net::SocketAddr;

use clap::{Arg, ArgAction, Command};
use clap::builder::Str;
use log::{debug, error, info, warn};
use tokio::join;
use tokio::net::TcpListener;

use crate::proxy::*;
use crate::rule::*;
use crate::utils::{combine, get_http_domain, get_https_domain, get_target_address};

mod utils;
mod prelude;
mod rule;
mod proxy;
mod rules;

const INSTALL_FILES: &[(&[u8], &str); 4] = &[
    (include_bytes!("../harmony-rs.service"), "/etc/systemd/system/harmony-rs.service"),
    (include_bytes!("../rules.json"), "/etc/harmony-rs/rules.json"),
    (include_bytes!("../post.sh"), "/etc/harmony-rs/post.sh"),
    (include_bytes!("../pre.sh"), "/etc/harmony-rs/pre.sh")
];

#[tokio::main]
async fn main() {
    let args = Command::new("https-proxy")
        .author("Mons W")
        .version("0.1.0")
        .arg(Arg::new("proxy")
            .long("proxy")
            .short('x')
            .default_value("127.0.0.1:1080")
            .action(ArgAction::Set)
            .required(false))
        .arg(Arg::new("rule")
            .long("rule-file")
            .action(ArgAction::Set).required(false))
        .arg(Arg::new("http-port")
            .long("http-port")
            .default_value("8080")
            .action(ArgAction::Set)
            .required(false))
        .arg(Arg::new("https-port")
            .long("https-port")
            .default_value("8433")
            .action(ArgAction::Set)
            .required(false))
        .arg(Arg::new("fwmark")
            .long("fwmark")
            .action(ArgAction::Set)
            .required(false))
        .arg(Arg::new("ctrl")
            .long("enable-control-pipe")
            .action(ArgAction::SetTrue)
            .help("enable control pipe")
            .required(false))
        .arg(Arg::new("debug")
            .long("debug")
            .action(ArgAction::SetTrue)
            .help("print debug level logs")
            .required(false))
        .subcommand(clap::
        Command::new("install")
            .about("automatically generate configuration files and systemd units to the system directory")
            .arg(Arg::new("overwrite")
                .long("overwrite")
                .action(ArgAction::SetTrue)
                .help("overwrite existing cfg file if set")
            )
        )
        .get_matches();
    if args.get_flag("debug") {
        // 初始化 Builder
        let mut builder = env_logger::Builder::new();

        // 设置日志级别
        builder.filter_level(log::LevelFilter::Debug);

        // 设置输出格式
        builder.format_timestamp(None);
        builder.format_module_path(false);

        // 初始化 env_logger
        builder.init();
        debug!("enable debug mode")
    } else {
        env_logger::init();
    }
    match args.subcommand() {
        Some(("install", installArgs)) => {
            let exe = std::env::current_exe().expect("failed to get current executable path");
            use std::path::Path;
            use std::fs;
            let cfg_home = Path::new("/etc/harmony-rs");
            info!("installing...");

            if !cfg_home.exists() {
                info!("create dir: /etc/harmony-rs");
                if let Err(e) = fs::create_dir(cfg_home) {
                    warn!("failed to create folder /etc/harmony-rs: {}", e);
                    process::exit(255);
                }
            }
            let overwrite = installArgs.get_flag("overwrite");
            for &(data, file) in INSTALL_FILES {
                if !overwrite && Path::new(file).exists() {
                    info!("ignore exist file: {}",file);
                    continue;
                }
                info!("cp {}",file);
                let mut service = String::new();
                let data = if file == "/etc/systemd/system/harmony-rs.service" {
                    service = std::str::from_utf8(data).unwrap()
                        .replace("/usr/local/bin/harmony-rs", exe.to_str().unwrap());
                    service.as_bytes()
                } else {
                    data
                };
                if let Err(e) = fs::write(file, data) {
                    warn!("write {} error: {}", file, e);
                    process::exit(255);
                }
            }
            return;
        }
        _ => {
            // done
        }
    }

    let proxy_address = args.get_one::<String>("proxy").unwrap();
    let proxy_address: SocketAddr = match proxy_address.parse() {
        Ok(addr) => addr,
        Err(err) => {
            error!("socks5 proxy address format error:{} {}",proxy_address,err);
            return;
        }
    };
    info!("proxy server:{}", proxy_address);
    let rule_file = args.get_one::<String>("rule").map(|s| s.to_string());
    let ctrl = std::env::var("CTRL_FILE")
        .unwrap_or("/run/harmony-rs".to_string());
    let ctrl: Option<String> = if args.get_flag("ctrl") { Some(ctrl) } else { None };
    let rule = match RuleEngine::from_file(rule_file, ctrl) {
        Ok(r) => { r }
        Err(err) => {
            error!("unable to load rule file: {}",err);
            return;
        }
    };
    let mut proxy = Proxy::from_addr(proxy_address, rule);
    if let Some(mark) = args.get_one::<String>("fwmark") {
        proxy.fwmark = mark.parse::<u16>().expect("fwmark must be a number");
        debug!("use fwmark: {}",proxy.fwmark);
    }

    let https_job = { // https 代理
        let port: &String = args.get_one("https-port").expect("https listening port is invalid");
        let bind = TcpListener::bind(format!("[::]:{}", port)).await.unwrap();
        let proxy_copy = proxy.clone();
        tokio::spawn(async move {
            loop {
                let (client, addr) = match bind.accept().await {
                    Ok(v) => {
                        v
                    }
                    Err(err) => {
                        warn!("service shutdown: {}",err);
                        return;
                    }
                };
                debug!("new connection: {}", addr);
                let p = proxy_copy.clone();
                tokio::spawn(async move {
                    p.handler_https(client).await;
                });
            }
        })
    };

    let http_job = {
        let port: &String = args.get_one("http-port").expect("http listening port is invalid");
        let bind = TcpListener::bind(format!("[::]:{}", port)).await.unwrap();
        let proxy_copy = proxy.clone();
        tokio::spawn(async move {
            loop {
                let (client, addr) = match bind.accept().await {
                    Ok(v) => {
                        v
                    }
                    Err(err) => {
                        warn!("service shutdown: {}",err);
                        return;
                    }
                };
                debug!("new connection: {}", addr);
                let p = proxy_copy.clone();
                tokio::spawn(async move {
                    p.handler_http(client).await;
                });
            };
        })
    };
    let (_, _) = join!(http_job,https_job);
}

