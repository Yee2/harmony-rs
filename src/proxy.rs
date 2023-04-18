use std::net::SocketAddr;

use anyhow::anyhow;
use log::{debug, trace, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{combine, get_http_domain, get_https_domain, get_target_address, RuleEngine};
use crate::prelude::*;

#[derive(Clone)]
pub struct Proxy {
    addr: SocketAddr,
    pub fwmark: u16,
    r: RuleEngine,
}

impl Proxy {
    pub fn new(server: &str, r: RuleEngine) -> Result<Self> {
        let proxy_address: SocketAddr = match server.parse() {
            Ok(addr) => addr,
            Err(err) => {
                return Err(anyhow!("proxy server address format error:{} {}",server,err));
            }
        };
        Ok(Proxy::from_addr(proxy_address, r))
    }
    pub fn from_addr(proxy_address: SocketAddr, r: RuleEngine) -> Self {
        Proxy { addr: proxy_address, fwmark: 0, r }
    }
    async fn connect(&self, target: &Target) -> Result<TcpStream> {
        Ok(target.connect_fwmark(self.fwmark).await?)
    }
    async fn dial(&self, target: &Target) -> Result<TcpStream> {
        trace!("proxy: {}",target);
        let mut connect = connect(self.addr, self.fwmark).await?;
        connect.write_all(&[0x05u8, 0x01, 0x00]).await?;
        let mut bb = [0u8; 2];
        connect.read_exact(&mut bb).await?;
        if (bb[0] as u16) << 8 | (bb[1] as u16) != 0x0500 {
            return Err(anyhow!("proxy server type not supported"));
        }
        match target {
            Target::IPv4(ip) => {
                let mut data = [0x05u8, 0x01, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, (ip.port() >> 8) as u8, ip.port() as u8];
                data[4..8].copy_from_slice(&ip.ip().octets());
                connect.write_all(&data).await?;
            }
            Target::IPv6(ip) => {
                let mut data: [u8; 22] = [0u8; 22];
                data[0] = 0x05;
                data[1] = 0x01;
                data[2] = 0x00;
                data[3] = 0x04;
                data[4..20].copy_from_slice(&ip.ip().octets());
                data[20] = (ip.port() >> 8) as u8;
                data[21] = ip.port() as u8;
                connect.write_all(&data).await?;
            }
            Target::Hostname(hostname) => {
                let (hostname, port) = hostname.split_once(":").unwrap();
                let port: u16 = port.parse()?;
                trace!("socks5 hostname:{} port:{}",hostname,port);
                let mut data = [0u8; 280];
                data[0] = 0x05;
                data[1] = 0x01;
                data[2] = 0x00;
                data[3] = 0x03;
                data[4] = hostname.len() as u8;
                data[5..5 + hostname.len()].copy_from_slice(hostname.as_bytes());
                data[5 + hostname.len()] = (port >> 8) as u8;
                data[6 + hostname.len()] = port as u8;
                connect.write_all(&data[..7 + hostname.len()]).await?;
            }
        }
        let mut b4 = [0u8; 4];
        connect.read_exact(&mut b4).await?;
        if b4[0] != 0x05 || b4[1] != 0x00 {
            return Err(anyhow!("proxy server authentication is not supported"));
        }
        match b4[3] {
            0x01 => {
                let mut b6 = [0u8; 6];
                connect.read_exact(&mut b6).await?;
            }
            0x03 => {
                let mut b6 = [0u8; 260];
                let n = connect.read_u8().await?;
                connect.read_exact(&mut b6[..n as usize]).await?;
            }
            0x04 => {
                let mut b6 = [0u8; 18];
                connect.read_exact(&mut b6).await?;
            }
            _ => {
                let mut b6 = [0u8; 6];
                connect.read_exact(&mut b6).await?;
            }
        }


        Ok(connect)
    }

    pub async fn handler_https(&self, client: TcpStream) {
        let peer = match client.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                warn!("get peer fault:{}",err);
                return;
            }
        };
        let dst = get_target_address(&client);
        let port: u16 = match dst {
            Some(addr) => {
                debug!("[https] {} <==> {}",peer,&addr);
                addr.port()
            }
            None => {
                debug!("[https] get target address error: {} ",peer);
                433
            }
        };
        let mut buf = [0u8; 1024];
        let size = client.peek(&mut buf).await.unwrap();
        let target: Target = match get_https_domain(&buf[..size]) {
            Ok(t) => {
                t.set_port(port)
            }
            Err(err) => {
                match dst {
                    Some(addr) => { addr.into() }
                    None => {
                        warn!("[https] unknown connect address:{} err:{}",peer,err);
                        return;
                    }
                }
            }
        };

        let connection = if self.r.check_target(&target).await {
            self.dial(&target).await
        } else {
            self.connect(&target).await
        };
        match connection {
            Ok(remote) => {
                combine(client, remote).await;
            }
            Err(err) => {
                warn!("[http] connection failed:{} ==> {}, err: {}",peer,target,err)
            }
        }
    }

    pub async fn handler_http(&self, mut client: TcpStream) {
        let peer = match client.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                warn!("get peer fault:{}",err);
                return;
            }
        };
        let (buf, target) = match get_http_domain(&mut client).await {
            Ok(v) => {
                debug!("[http] {} <==> {}",peer,&v.1);
                v
            }
            Err(err) => {
                debug!("[http] get target address error: {}, msg: {} ",peer,err);
                return;
            }
        };
        let connection = if self.r.check_target(&target).await {
            self.dial(&target).await
        } else {
            self.connect(&target).await
        };
        match connection {
            Ok(mut remote) => {
                if cfg!(debug_assertions) {
                    if let Ok(request) = std::str::from_utf8(buf.bytes()) {
                        trace!("http request:{}",request.replace("\r\n","\\r\\n"));
                    }
                }
                remote.write_all(buf.bytes()).await.unwrap();
                combine(client, remote).await;
            }
            Err(err) => {
                warn!("[http] connection failed:{} ==> {}, err: {}",peer,target,err)
            }
        }
    }
}

