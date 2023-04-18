use std::fmt::{Display, Formatter};
use std::io::Error;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::os::unix::prelude::AsRawFd;

use anyhow::anyhow;
use log::{debug, trace};
use tokio::net::{TcpSocket, TcpStream};

pub type Result<T> = anyhow::Result<T>;

pub async fn connect(addr: SocketAddr, fwmark: u16) -> Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    #[cfg(unix)]
    if fwmark > 0 {
        let m = fwmark as u32;
        let ret = unsafe {
            libc::setsockopt(socket.as_raw_fd(),
                             libc::SOL_SOCKET,
                             libc::SO_MARK,
                             &m as *const u32 as *const libc::c_void,
                             mem::size_of_val(&m) as libc::socklen_t,
            )
        };
        if ret != 0 {
            debug!("setsockopt error:{}",Error::last_os_error());
        }
    }
    return Ok(socket.connect(addr).await?);
}

pub enum Target {
    Hostname(String),
    IPv4(SocketAddrV4),
    IPv6(SocketAddrV6),
}

impl Display for Target {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Hostname(hostname) => write!(f, "{}", hostname.as_str()),
            Target::IPv4(ip) => write!(f, "{}", ip),
            Target::IPv6(ip) => write!(f, "{}", ip),
        }
    }
}

impl Target {
    fn to_addr(&self) -> Result<SocketAddr> {
        Ok(match &self {
            Target::Hostname(hostname) => {
                hostname.to_socket_addrs()?.next()
                    .ok_or(anyhow!("unable to resolve domain name: {}",hostname))?
            }
            Target::IPv4(v) => {
                SocketAddr::V4(*v)
            }
            Target::IPv6(v) => {
                SocketAddr::V6(*v)
            }
        })
    }
    pub async fn connect(&self) -> Result<TcpStream> {
        let addr: SocketAddr = self.to_addr()?;
        trace!("connecting: {} ...",&addr);
        let connect = TcpStream::connect(addr).await?;
        Ok(connect)
    }
    pub async fn connect_fwmark(&self, fwmark: u16) -> Result<TcpStream> {
        let addr: SocketAddr = self.to_addr()?;
        trace!("connecting: {} ...",&addr);
        let connect = connect(addr, fwmark).await?;
        Ok(connect)
    }
}

impl From<SocketAddr> for Target {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Target::IPv4(v4.into()),
            SocketAddr::V6(v6) => Target::IPv6(v6.into()),
        }
    }
}