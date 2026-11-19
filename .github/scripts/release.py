"""解析发布清单并上传版本资产。重跑只补齐草稿中缺失的文件。"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


def gh(*args, **kwargs):
    return subprocess.run(["gh", *args], check=True, text=True, encoding="utf-8", **kwargs)


def read_release(tag):
    try:
        result = gh("release", "view", tag, "--json", "isDraft,assets", capture_output=True)
    except subprocess.CalledProcessError as error:
        if error.stderr.strip() == "release not found":
            return None
        raise ValueError(f"无法查询发布 {tag}：{error.stderr.strip()}") from error
    return json.loads(result.stdout)


def resolve_scope(tag, cargo_version, web_version, manifest):
    version = tag.removeprefix("v")
    if not tag.startswith("v") or not version:
        raise ValueError("发布标签必须使用 v<版本号> 格式")
    if version != cargo_version or version != web_version or version != manifest["version"]:
        raise ValueError(
            f"标签、Cargo、Web 和发布清单版本不一致："
            f"tag={version} cargo={cargo_version} web={web_version} manifest={manifest['version']}"
        )
    components = manifest["components"]
    if not isinstance(components, list) or not components or any(
        component not in ("server", "agent", "node") for component in components
    ) or len(components) != len(set(components)):
        raise ValueError("发布清单须声明一个或多个实际变化的组件，每个组件仅声明一次")
    node = "node" in components
    if node and manifest["node_version"] != version:
        raise ValueError("节点发布版本必须与本次构建版本一致")
    return version, components, node, [item for item in components if item != "node"]


def scope():
    tag = os.environ["GITHUB_REF_NAME"]
    version, components, node, images = resolve_scope(
        tag,
        tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"],
        json.loads(Path("web/package.json").read_text(encoding="utf-8"))["version"],
        json.loads(Path("release-manifest.json").read_text(encoding="utf-8")),
    )
    release = read_release(tag)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        for key, value in {
            "version": version,
            "components": json.dumps(components),
            "node": json.dumps(node),
            "images": json.dumps(images),
            "published": json.dumps(release is not None and not release["isDraft"]),
        }.items():
            print(f"{key}={value}", file=output)


def archive_names(version, components):
    names = []
    if "node" in components:
        names.extend(f"nexo-node-{version}-linux-{arch}.tar.gz" for arch in ("x86_64", "aarch64"))
    if any(item in components for item in ("server", "agent")):
        names.append(f"nexo-v{version}-docker.tar.gz")
    return sorted(names)


def checksums(directory, names):
    lines = []
    for name in names:
        with (directory / name).open("rb") as asset:
            digest = hashlib.file_digest(asset, "sha256").hexdigest()
        lines.append(f"{digest}  {name}\n")
    return "".join(lines)


def publish(version, components, directory):
    tag = f"v{version}"
    release = read_release(tag)
    archives = archive_names(version, components)
    expected = set(archives) | {"SHA256SUMS"}
    existing = {item["name"] for item in release["assets"]} if release else set()
    published = release is not None and not release["isDraft"]
    if existing - expected or ((published or "SHA256SUMS" in existing) and existing != expected):
        raise ValueError(f"{tag} 的既有资产与本次发布范围不符")

    # 重跑时以已上传的文件为准。校验清单最后上传，防止中断后混用不同构建。
    with tempfile.TemporaryDirectory(dir=directory) as staging:
        for name in sorted(existing):
            gh("release", "download", tag, "--pattern", name, "--dir", staging)
            (Path(staging) / name).replace(directory / name)

    sums = checksums(directory, archives)
    checksum_path = directory / "SHA256SUMS"
    if "SHA256SUMS" in existing:
        uploaded = checksum_path.read_text(encoding="utf-8")
        if sorted(uploaded.splitlines()) != sorted(sums.splitlines()):
            raise ValueError(f"{tag} 的既有资产校验失败")
    else:
        checksum_path.write_text(sums, encoding="utf-8")
    if published:
        print(f"已验证正式发布 {tag} 的全部资产")
        return

    notes = str(directory / "release-notes.md")
    if release is None:
        gh("release", "create", tag, "--draft", "--verify-tag", "--title", f"Nexo {tag}", "--notes-file", notes)
    missing = [str(directory / name) for name in archives if name not in existing]
    if missing:
        gh("release", "upload", tag, *missing)
    if "SHA256SUMS" not in existing:
        gh("release", "upload", tag, str(checksum_path))
    gh("release", "edit", tag, "--draft=false")


if __name__ == "__main__":
    try:
        if sys.argv[1] == "scope":
            scope()
        elif sys.argv[1] == "publish":
            publish(os.environ["VERSION"], json.loads(os.environ["COMPONENTS"]), Path("dist"))
        else:
            raise ValueError("仅支持 scope 或 publish")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"发布失败：{error}")
