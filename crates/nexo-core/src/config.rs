//! 启动配置只在启动时读取；首次生成不覆盖已有文件，解析错误不包含原始凭据。
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::{
    io::Write,
    path::{Path, PathBuf},
};

pub fn load<T: DeserializeOwned>(path: &Path, template: &str) -> Result<T> {
    if !path.try_exists().context("无法检查配置文件")? {
        let parent = path.parent().context("配置文件缺少父目录")?;
        std::fs::create_dir_all(parent).context("无法创建配置目录")?;
        let mut file = tempfile::NamedTempFile::new_in(parent).context("无法创建配置临时文件")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(template.as_bytes())
            .context("无法写入默认配置")?;
        file.as_file().sync_all().context("无法同步默认配置")?;
        match file.persist_noclobber(path) {
            Ok(_) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => anyhow::bail!("无法保存配置文件：{}", path.display()),
        }
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("无法读取配置文件：{}", path.display()))?;
    serde_path_to_error::deserialize(toml::Deserializer::new(&text)).map_err(
        |error: serde_path_to_error::Error<toml::de::Error>| {
            let e = error.inner();
            let offset = e.span().map(|v| v.start).unwrap_or(0).min(text.len());
            let line = text.as_bytes()[..offset]
                .iter()
                .filter(|&&c| c == b'\n')
                .count()
                + 1;
            // 只补充未知字段名，不能直接打印 TOML 错误正文，正文可能含密码等原始值。
            let mut field = error.path().to_string();
            if let Some(name) = e
                .message()
                .strip_prefix("unknown field `")
                .and_then(|s| s.split('`').next())
            {
                if field == "." {
                    field.clear();
                }
                if !field.is_empty() {
                    field.push('.');
                }
                field.push_str(name);
            }
            anyhow::anyhow!(
                "配置文件 {} 第 {} 行字段 {} 格式或类型不正确，请核对模板",
                path.display(),
                line,
                field
            )
        },
    )
}

pub fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}

pub fn relative_to(config: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_owned()
    } else {
        config.parent().unwrap_or(Path::new(".")).join(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Example {
        enabled: bool,
    }

    #[test]
    fn creates_once_and_preserves_comments_and_invalid_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(
            load::<Example>(&path, "# 默认\nenabled = true\n")
                .unwrap()
                .enabled
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        for text in [
            "# 手动排版\nenabled=false\n",
            "enabled='secret-that-must-not-be-logged'",
            "unknown=true",
            "enabled=[",
        ] {
            std::fs::write(&path, text).unwrap();
            let result = load::<Example>(&path, "enabled=true");
            if text.starts_with('#') {
                assert!(!result.unwrap().enabled);
            } else {
                let error = result.err().unwrap().to_string();
                assert!(!error.contains("secret-that-must-not-be-logged"));
                assert!(error.contains("第 1 行"));
                if text.starts_with("unknown") {
                    assert!(error.contains("unknown"));
                }
            }
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
        let blocked = dir.path().join("blocked");
        std::fs::write(&blocked, "keep").unwrap();
        assert!(load::<Example>(&blocked.join("config.toml"), "enabled=true").is_err());
        assert_eq!(std::fs::read_to_string(blocked).unwrap(), "keep");
    }
}
