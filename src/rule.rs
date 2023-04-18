use std::{fs, thread};
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, Error, Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use libc::mode_t;
use log::{debug, info, trace, warn};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::join;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio::sync::mpsc::Sender;
use url::quirks::hostname;

use crate::prelude::*;
use crate::rules::Rules;
use crate::utils::just_hostname;

struct Filter {
    rules: Rules,
}

impl Filter {
    fn insert(&mut self, hostname: &str) {
        self.rules.add(hostname);
    }
    fn check_domain(&self, hostname: &str) -> bool {
        self.rules.contain(hostname)
    }
}

fn new_rules() -> Filter {
    Filter { rules: Rules::new() }
}

fn load_rules(file: &str) -> Result<Filter> {
    debug!("rule file:{}",file);
    Ok(Filter { rules: Rules::from_file(file)? })
}

enum FilterControl {
    Query(String, oneshot::Sender<bool>),
    Insert(String),
}

#[derive(Clone)]
pub struct RuleEngine(mpsc::Sender<FilterControl>);


impl RuleEngine {
    async fn sock(tx: Sender<FilterControl>, filename: &str) -> Result<()> {
        let socket_path = Path::new(filename);
        if socket_path.exists() {
            fs::remove_file(socket_path)
                .expect("the named pipe already exists and cannot be deleted");
        }
        let path = CString::new(filename)
            .expect("error occurred when converting named pipe file path to CString type");
        debug!("create named pipe: {}",filename);
        let mode: mode_t = libc::S_IWUSR | libc::S_IWGRP | libc::S_IWOTH;
        if unsafe { libc::mkfifo(path.as_ptr(), mode) } != 0 {
            let e = Error::last_os_error();
            return Err(anyhow!("failed to create named pipe: {}",e));
        }

        let filename_cp = String::from(filename);
        let path = socket_path.to_path_buf();
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let mut rt = Builder::new_current_thread().enable_all().build().unwrap();
            loop {
                let f = std::fs::File::open(path.as_path())
                    .expect(format!("cannot open named pipe: {}", filename_cp).as_str());
                let mut reader = std::io::BufReader::new(f);
                for line in reader.lines() {
                    let Ok(hostname) = line else { break; };
                    let hostname: String =
                        if hostname.starts_with("https://") || hostname.starts_with("http://") {
                            url::Url::parse(hostname.as_str())
                                .ok()
                                .and_then(|u| u.domain().map(|h| h.to_string()))
                                .unwrap_or(hostname)
                        } else {
                            hostname
                        };
                    rt.block_on(async {
                        let _ = tx.send(FilterControl::Insert(hostname)).await;
                    });
                }
            }
        });
        // 逐行读取文件
        return Ok(());
    }
    pub fn from_file(filename: Option<String>, sock: Option<String>) -> Result<Self> {
        let mut filter = if let Some(f) = filename {
            let r = load_rules(f.as_str())?;
            info!("loading rules completed");
            r
        } else {
            new_rules()
        };
        let (tx, mut rx) = mpsc::channel::<FilterControl>(10);
        let job1 = tokio::spawn(async move {
            while let Some(ctr) = rx.recv().await {
                match ctr {
                    FilterControl::Query(hostname, reply) => {
                        let _ = reply.send(filter.check_domain(hostname.as_str()));
                    }
                    FilterControl::Insert(hostname) => {
                        filter.rules.add(hostname.as_str())
                    }
                }
            }
            panic!("channel closed!")
        });
        let txx = tx.clone();
        let job2 = tokio::spawn(async move {
            let Some(path) = sock else { return; };
            let _ = RuleEngine::sock(txx, path.as_str()).await;
        });
        thread::spawn(move || {
            let rt = Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                join!(job1,job2)
            });
        });
        Ok(RuleEngine(tx))
    }
    pub async fn check_target(&self, t: &Target) -> bool {
        let Target::Hostname(hostname) = t else { return false; };
        let (tx, rx) = oneshot::channel::<bool>();
        let msg = FilterControl::Query(just_hostname(hostname.clone()).to_string(), tx);
        if let Err(e) = self.0.send(msg).await {
            warn!("Query domain err:{}",e);
            return false;
        }
        let Ok(result) = rx.await else { return false; };
        trace!("check domain:{} {}",hostname,result);
        return result;
    }
}