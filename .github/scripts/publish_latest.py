"""将已发布的数字版本原样指向 latest；不构建镜像、不修改数字标签。"""

import argparse
import base64
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request


MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def stable_version(tag):
    """只比较稳定版的数字部分，避免字符串排序将 0.2.9 排在 0.2.10 后面。"""
    if not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag):
        return None
    return tuple(map(int, tag.split(".")))


class Registry:
    """凭据仅用于 GHCR 请求；分页和 manifest 原文保留，错误不输出认证内容。"""

    def __init__(self, repository, username, password, apply):
        self.base = f"https://ghcr.io/v2/{repository}/"
        scope = f"repository:{repository}:pull" + (",push" if apply else "")
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        request = urllib.request.Request(
            "https://ghcr.io/token?" + urllib.parse.urlencode({"service": "ghcr.io", "scope": scope}),
            headers={"Authorization": f"Basic {auth}"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            self.token = json.load(response)["token"]

    def request(self, path, data=None, content_type=None):
        headers = {"Authorization": f"Bearer {self.token}", "Accept": MANIFEST_TYPES}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers, method="PUT" if data is not None else "GET",
        )
        return urllib.request.urlopen(request, timeout=30)

    def tags(self):
        tags = []
        path = "tags/list?n=100"
        while path:
            with self.request(path) as response:
                tags.extend(json.load(response).get("tags") or [])
                link = response.headers.get("Link", "")
            next_link = re.search(r'<([^>]+)>;\s*rel="?next"?', link)
            path = None
            if next_link:
                url = urllib.parse.urljoin(self.base + "tags/list", next_link[1])
                if not url.startswith(self.base):
                    raise RuntimeError("GHCR 分页地址不属于当前镜像仓库")
                path = url[len(self.base):]
        return tags

    def manifest(self, tag):
        try:
            with self.request(f"manifests/{tag}") as response:
                return response.read(), response.headers["Content-Type"], response.headers["Docker-Content-Digest"]
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def alias(self, manifest):
        body, content_type, _ = manifest
        with self.request("manifests/latest", body, content_type):
            pass


def promote(registry, version, apply=False):
    """仅允许仓库中最新稳定版前进到 latest；读取失败时停止，绝不猜测旧状态。"""
    candidate = stable_version(version)
    if candidate is None:
        return "跳过预发布版本"
    versions = [parsed for tag in registry.tags() if (parsed := stable_version(tag)) is not None]
    if versions and candidate < max(versions):
        return "跳过历史版本，latest 不倒退"
    source = registry.manifest(version)
    if source is None:
        raise RuntimeError(f"正式镜像 {version} 不存在")
    current = registry.manifest("latest")
    if current and current[2] == source[2]:
        return f"latest 已指向 {version}（{source[2]}）"
    if not apply:
        return f"待将 latest 指向 {version}（{source[2]}）"
    registry.alias(source)
    result = registry.manifest("latest")
    if result is None or result[2] != source[2]:
        raise RuntimeError("latest 摘要与正式镜像不一致")
    return f"latest 已指向 {version}（{source[2]}）"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--components", nargs="+", choices=["server", "agent"], required=True)
    parser.add_argument("--apply", action="store_true", help="实际更新 latest；默认只核对")
    args = parser.parse_args()
    if stable_version(args.version) is None:
        if not re.fullmatch(r"\d+\.\d+\.\d+-[\w.-]+", args.version):
            parser.error("版本必须为数字稳定版或带后缀的预发布版")
        print("预发布版本不更新 latest")
        return
    password = os.environ.get("GH_TOKEN") or subprocess.check_output(["gh", "auth", "token"], text=True).strip()
    username = os.environ.get("GITHUB_ACTOR") or subprocess.check_output(["gh", "api", "user", "--jq", ".login"], text=True).strip()
    for component in dict.fromkeys(args.components):
        repository = f"thelinyue/nexo-{component}"
        print(f"{repository}: {promote(Registry(repository, username, password, args.apply), args.version, args.apply)}")


if __name__ == "__main__":
    main()
