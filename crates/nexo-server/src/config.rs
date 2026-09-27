//! Server 启动配置与页面设置分开：在此读取 TOML 和管理员初始化环境变量，运行模块只使用解析结果。
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub control_addr: SocketAddr,
    pub tunnel_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub public_bind: IpAddr,
    pub tunnel_endpoint: String,
    pub udp_endpoint: String,
    pub runtime_dir: PathBuf,
    pub web_dir: PathBuf,
    pub admin: Admin,
    pub caddy: Caddy,
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Admin {
    pub username: String,
    pub password: String,
}
impl Default for Admin {
    fn default() -> Self {
        Self {
            username: "admin".into(),
            password: String::new(),
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Caddy {
    pub enabled: bool,
    pub binary: PathBuf,
    pub admin_url: String,
    pub http_listen: String,
    pub https_listen: String,
}
impl Default for Caddy {
    fn default() -> Self {
        Self {
            enabled: true,
            binary: "caddy".into(),
            admin_url: "http://127.0.0.1:8290".into(),
            http_listen: ":80".into(),
            https_listen: ":443".into(),
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            http_addr: "0.0.0.0:8280".parse().unwrap(),
            control_addr: "0.0.0.0:9890".parse().unwrap(),
            tunnel_addr: "0.0.0.0:9891".parse().unwrap(),
            udp_addr: "0.0.0.0:9891".parse().unwrap(),
            public_bind: "0.0.0.0".parse().unwrap(),
            tunnel_endpoint: String::new(),
            udp_endpoint: String::new(),
            runtime_dir: "/run/nexo".into(),
            web_dir: PathBuf::new(),
            admin: Admin::default(),
            caddy: Caddy::default(),
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut value: Self =
            nexo_core::config::load(path, include_str!("../../../config/server.toml"))?;
        // 仅管理员首次初始化兼容环境变量；非空值逐项覆盖 TOML，不回写配置文件。
        // 已有账号仍由 ensure_admin 保留，重启时不会用初始凭据重置密码。
        if let Ok(username) = std::env::var("NEXO_ADMIN_USERNAME") {
            if !username.is_empty() {
                value.admin.username = username;
            }
        }
        if let Ok(password) = std::env::var("NEXO_ADMIN_PASSWORD") {
            if !password.is_empty() {
                value.admin.password = password;
            }
        }
        for (name, address) in [
            ("tunnel_endpoint", &value.tunnel_endpoint),
            ("udp_endpoint", &value.udp_endpoint),
        ] {
            if !address.is_empty() {
                validate_endpoint(name, address)?;
            }
        }
        anyhow::ensure!(
            !value.caddy.binary.as_os_str().is_empty(),
            "caddy.binary 不能为空"
        );
        let admin =
            reqwest::Url::parse(&value.caddy.admin_url).context("caddy.admin_url 格式错误")?;
        anyhow::ensure!(
            admin.scheme() == "http"
                && admin
                    .host_str()
                    .and_then(|s| s.trim_matches(['[', ']']).parse::<IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
                && admin.username().is_empty()
                && admin.password().is_none()
                && admin.path() == "/"
                && admin.query().is_none()
                && admin.fragment().is_none(),
            "caddy.admin_url 必须是本机回环 IP 的 HTTP 地址"
        );
        for (name, address) in [
            ("caddy.http_listen", &value.caddy.http_listen),
            ("caddy.https_listen", &value.caddy.https_listen),
        ] {
            let socket = if address.starts_with(':') {
                format!("0.0.0.0{address}")
            } else {
                address.clone()
            };
            anyhow::ensure!(
                socket.parse::<SocketAddr>().is_ok(),
                "{name} 必须是 IP:端口或 :端口"
            );
        }
        anyhow::ensure!(
            !value.runtime_dir.as_os_str().is_empty(),
            "runtime_dir 不能为空"
        );
        value.runtime_dir = nexo_core::config::relative_to(path, &value.runtime_dir);
        value.web_dir = if value.web_dir.as_os_str().is_empty() {
            let installed = std::env::current_exe()?
                .parent()
                .context("无法定位程序目录")?
                .join("web");
            if installed.is_dir() {
                installed
            } else {
                std::env::current_dir()?.join("web/dist")
            }
        } else {
            nexo_core::config::relative_to(path, &value.web_dir)
        };
        if value.caddy.binary.components().count() > 1 {
            value.caddy.binary = nexo_core::config::relative_to(path, &value.caddy.binary);
        }
        Ok(value)
    }
}

fn validate_endpoint(name: &str, address: &str) -> Result<()> {
    let url = reqwest::Url::parse(&format!("tcp://{address}"));
    anyhow::ensure!(
        url.is_ok_and(|u| u.host_str().is_some()
            && u.port().is_some_and(|p| p > 0)
            && u.username().is_empty()
            && u.password().is_none()
            && u.path().is_empty()
            && u.query().is_none()
            && u.fragment().is_none()),
        "{name} 必须是主机:端口，IPv6 使用 [地址]:端口"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_relative_paths_ipv6_and_field_errors() {
        let dir = std::env::temp_dir().join(format!("nexo-config-{}", uuid::Uuid::new_v4()));
        let path = dir.join("server.toml");
        let config = Config::load(&path).unwrap();
        assert_eq!(config.http_addr.to_string(), "0.0.0.0:8280");
        assert!(config.caddy.enabled);
        let original = std::fs::read(&path).unwrap();
        Config::load(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::write(&path, "runtime_dir='run'\nweb_dir='assets'\n[caddy]\nbinary='./bin/caddy'\nadmin_url='http://[::1]:8290'").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.runtime_dir, dir.join("run"));
        assert_eq!(config.web_dir, dir.join("assets"));
        assert_eq!(config.caddy.binary, dir.join("./bin/caddy"));
        for (text, field) in [
            ("http_addr='invalid'", "http_addr"),
            ("tunnel_endpoint='https://wrong'", "tunnel_endpoint"),
            ("runtime_dir=''", "runtime_dir"),
            (
                "[caddy]\nadmin_url='http://0.0.0.0:8290'",
                "caddy.admin_url",
            ),
            ("[admin]\npassword=['hidden-secret']", "admin.password"),
        ] {
            std::fs::write(&path, text).unwrap();
            let error = Config::load(&path).err().unwrap().to_string();
            assert!(error.contains(field), "{error}");
            assert!(!error.contains("hidden-secret"));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
