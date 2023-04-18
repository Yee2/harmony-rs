use std::io::Error;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};

use anyhow::anyhow;
use async_recursion::async_recursion;
use log::{debug, trace, warn};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

use prelude::Result;

use crate::prelude;
use crate::prelude::Target;

#[cfg(unix)]
pub fn get_target_address(s: &TcpStream) -> Option<SocketAddr> {
    let fd: RawFd = s.as_raw_fd();
    let local_addr = match s.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            warn!("could not get local address:{}",err);
            return None;
        }
    };
    let is_v4 = if let IpAddr::V6(v6) = local_addr.ip() {
        u128::from_be_bytes(v6.octets()) >> 32 == 0xffff
    } else {
        local_addr.is_ipv4()
    };
    if is_v4 {
        let mut data: libc::sockaddr_in = libc::sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0u8; 8],
        };
        let p = &mut data as *mut libc::sockaddr_in;
        let mut size = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(fd, libc::SOL_IP, libc::SO_ORIGINAL_DST,
                             p as *mut libc::c_void, &mut size as *mut libc::socklen_t)
        };
        if r == 0 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from((data.sin_addr.s_addr as u32).to_be())), (data.sin_port as u16).to_be());
            return Some(addr);
        }
    } else {
        let mut data: libc::sockaddr_in6 = libc::sockaddr_in6 {
            sin6_family: 0,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
            sin6_scope_id: 0,
        };
        let p = &mut data as *mut libc::sockaddr_in6;
        let mut size = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(fd, libc::SOL_IPV6, libc::IP6T_SO_ORIGINAL_DST,
                             p as *mut libc::c_void, &mut size as *mut libc::socklen_t)
        };
        if r == 0 {
            let ip = Ipv6Addr::from(u128::from_be_bytes(data.sin6_addr.s6_addr));
            let addr = SocketAddr::new(IpAddr::V6(ip), (data.sin6_port as u16).to_be());
            return Some(addr);
        }
    }
    debug!("syscall error:{}",Error::last_os_error());
    return None;
}

#[cfg(not(unix))]
pub fn get_target_address(s: &TcpStream) -> Option<SocketAddr> {
    trace!("not unix,unable to get destination address");
    None
}

pub fn get_https_domain(buf: &[u8]) -> Result<Target> {
    let max = buf.len();
    if max < 43 {
        return Err(anyhow!("packet length is too short"));
    }
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return Err(anyhow!("this is not a valid tls packet"));
    }
    let mut i: usize = 43;
    i += 1 + buf[i] as usize;
    if i >= max {
        return Err(anyhow!("corrupted data package"));
    }
    i += 2 + ((buf[i] as usize) << 8 | (buf[i + 1] as usize));
    if i >= max {
        return Err(anyhow!("corrupted data package"));
    }
    i += 1 + (buf[i] as usize);
    if i >= max {
        return Err(anyhow!("corrupted data package"));
    }
    let end: usize = i + 2 + ((buf[i] as usize) << 8 | (buf[i + 1] as usize)); // extensions end
    i += 2;                                   // extensions start
    if i >= max {
        return Err(anyhow!("corrupted data package"));
    }
    while i <= end {
        if i == end {
            return Err(anyhow!("https request hostname not found"));
        } else if i > end {
            return Err(anyhow!("packet is corrupted"));
        }
        if buf[i] == 0x00 && buf[i + 1] == 0x00 {
            let next: usize = i + 4 + ((buf[i + 2] as usize) << 8 | (buf[i + 3] as usize));
            if buf[i + 6] != 0x00 {
                return Err(anyhow!("unknown address type:{}", buf[i + 6]));
            }
            let name_length: usize = (buf[i + 7] as usize) << 8 | (buf[i + 8] as usize);
            if i + 9 + name_length != next {
                return Err(anyhow!("data length mismatch"));
            }
            if i + 9 + name_length > end {
                return Err(anyhow!("data length mismatch"));
            }
            let hostname = std::str::from_utf8(&buf[i + 9..i + 9 + name_length])?;
            trace!("https request hostname:{}",hostname);
            return Ok(Target::Hostname(String::from(hostname)));
        }
        i += 4 + ((buf[i + 2] as usize) << 8 | (buf[i + 3] as usize))
    }
    return Err(anyhow!("https request hostname not found"));
}

pub async fn get_http_domain(client: &mut TcpStream) -> Result<(Buffer, Target)> {
    let mut buf = Buffer {
        data: [0u8; 4096],
        pos: 0,
        cap: 0,
    };
    let dst = get_target_address(&client); // http
    let port = match dst {
        Some(addr) => {
            trace!("target address:{}",addr);
            addr.port()
        }
        None => 80
    };
    let _ = buf.read_line(client).await?;// 读取第一行
    loop {
        match buf.read_line(client).await {
            Ok(line) => {
                let (k, v) = sp(line);
                if k == "Host" {
                    // 如果 http 请求已经携带端口，使用请求头里面的端口信息
                    // 如果没有则尝试获取源请求端口
                    if v.contains(":") {
                        return Ok((buf, Target::Hostname(v)));
                    }
                    return Ok((buf, Target::Hostname(v).set_port(port)));
                }
            }
            Err(err) => {
                return match dst {
                    Some(addr) => {
                        Ok((buf, addr.into()))
                    }
                    None => {
                        Err(anyhow!("unable to get http request hostname: {}",err))
                    }
                };
            }
        }
    }
}

impl Target {
    #[inline]
    pub fn set_port(self, p: u16) -> Target {
        match self {
            Target::Hostname(hostname) => {
                Target::Hostname(format!("{}:{}", just_hostname(hostname), p))
            }
            Target::IPv4(mut ip) => {
                ip.set_port(p);
                self
            }
            Target::IPv6(mut ip) => {
                ip.set_port(p);
                self
            }
        }
    }
}

#[inline]
pub fn just_hostname(hostname: String) -> String {
    if hostname.contains(":") {
        let (hostname, _) = hostname.split_once(":").unwrap();
        return String::from(hostname);
    }
    return hostname;
}

pub async fn combine(mut client: TcpStream, mut target: TcpStream) {
    // connect to the target
    let (mut r1, mut w1) = client.split();
    let (mut r2, mut w2) = target.split();
    let (n1, n2) = tokio::join!(tokio::io::copy(&mut r1, &mut w2), tokio::io::copy(&mut r2, &mut w1));
    debug!(
        "=> send: {} bytes, receive:{} bytes",
        n1.unwrap_or_default(),
        n2.unwrap_or_default()
    );
}

pub struct Buffer {
    data: [u8; 4096],
    pos: usize,
    cap: usize,
}

impl Buffer {
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.cap]
    }
    #[async_recursion]
    async fn read_line<R>(&mut self, r: &mut R) -> Result<&str> where R: AsyncRead + Send + Sync + Unpin {
        for i in self.pos..self.cap {
            if self.data[i] == '\n' as u8 {
                let start = self.pos;
                let end = if i > 0 && self.data[i - 1] == '\r' as u8 {
                    i - 1
                } else { i };
                self.pos = i + 1;
                let row: &str = std::str::from_utf8(&self.data[start..end])?;
                return Ok(row);
            }
        }
        if self.cap >= self.data.len() {
            return Err(anyhow!("data length exceeded:{}",self.data.len()));
        }
        let n = r.read(&mut self.data[self.pos..]).await?;
        if n == 0 {
            return Err(anyhow!("connection has been closed"));
        }
        self.cap += n;
        self.read_line(r).await
    }
}

fn sp(line: &str) -> (String, String) {
    match line.split_once(':') {
        Some((k, v)) => (String::from(k), String::from(v.trim())),
        None => (String::from(line), String::new())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use crate::prelude::Target;
    use crate::utils::{Buffer, get_https_domain, sp};

    #[test]
    fn start() {
        let data = [0x16u8, 0x03, 0x01, 0x00, 0xa5,
            0x01, 0x00, 0x00, 0xa1,
            0x03, 0x03,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x00,
            0x00, 0x20, 0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a,
            0x01, 0x00,
            0x00, 0x58,
            0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74,
            0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
            0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03,
            0xff, 0x01, 0x00, 0x01, 0x00,
            0x00, 0x12, 0x00, 0x00];
        match get_https_domain(&data).unwrap() {
            Target::Hostname(hostname) => {
                assert_eq!(hostname, "example.ulfheim.net");
            }
            _ => {}
        }
    }

    #[tokio::test]
    async fn test_buffer_read_line() {
        let data = "hello\nworld\r\n".as_bytes().to_vec();
        let mut buffer = Buffer { data: [0u8; 4096], cap: 11, pos: 0 };
        let mut reader = &data[..];
        let line1 = buffer.read_line(&mut reader).await.unwrap();
        assert_eq!(line1, "hello");
        let line2 = buffer.read_line(&mut reader).await.unwrap();
        assert_eq!(line2, "world");
        let result = buffer.read_line(&mut reader).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_sp() {
        let line1 = "key:value";
        let (k1, v1) = sp(line1);
        assert_eq!(k1, "key");
        assert_eq!(v1, "value");
        let line2 = "key: value ";
        let (k2, v2) = sp(line2);
        assert_eq!(k2, "key");
        assert_eq!(v2, "value");
        let line3 = "key";
        let (k3, v3) = sp(line3);
        assert_eq!(k3, "key");
        assert_eq!(v3, "");
    }
}

