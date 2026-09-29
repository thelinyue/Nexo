#!/usr/bin/env python3
"""固定功能的本机更新助手：仅从官方 Release 安装数字版本，不执行控制器传入的命令。"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path('/opt/nexo-node')
STATE = Path('/var/lib/nexo-node-update')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
TASK = re.compile(r'[a-zA-Z0-9-]{1,100}\Z')
FILES = {'nexo-server', 'caddy', 'node-updater.py', 'LICENSE', 'THIRD_PARTY_NOTICES.md'}


def read_json(path):
    # 在同一文件描述符上检查并限长读取，拒绝链接、FIFO 和检查后替换。
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16384:
            raise ValueError('任务文件类型或大小无效')
        data = source.read(16385)
        if len(data) > 16384:
            raise ValueError('任务文件过大')
        return json.loads(data)


def write_status(task, stage, error=None, **details):
    value = dict(task_id=task, stage=stage, error=error, **details)
    temporary = STATE/'status.tmp'
    with temporary.open('w', encoding='utf-8') as output:
        json.dump(value, output, ensure_ascii=False)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(0o644)
    os.replace(temporary, STATE/'status.json')
    descriptor = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def download(url, path):
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.url.startswith('https://'):
            raise ValueError('拒绝非 HTTPS 下载')
        with path.open('wb') as target:
            shutil.copyfileobj(response, target)


def validate_archive(archive):
    members = archive.getmembers()
    if len(members) != len(FILES) or {m.name for m in members} != FILES:
        raise ValueError('安装包文件清单无效')
    if any(not m.isfile() or m.size > 300 * 1024 * 1024 for m in members):
        raise ValueError('安装包包含链接或过大文件')
    return members


def prepare(version):
    architecture = platform.machine()
    if architecture not in ('x86_64', 'aarch64'):
        raise ValueError('节点架构不支持')
    destination = ROOT/'releases'/version
    if destination.exists():
        if destination.is_symlink():
            raise ValueError('版本目录不允许符号链接')
        return destination
    with tempfile.TemporaryDirectory(dir=ROOT/'releases') as directory:
        directory = Path(directory)
        name = f'nexo-node-{version}-linux-{architecture}.tar.gz'
        url = f'https://github.com/thelinyue/Nexo/releases/download/v{version}'
        download(f'{url}/{name}', directory/name)
        download(f'{url}/SHA256SUMS', directory/'SHA256SUMS')
        checksums = dict((p[1].lstrip('*'), p[0]) for p in (line.split() for line in (directory/'SHA256SUMS').read_text().splitlines()) if len(p) == 2)
        if hashlib.sha256((directory/name).read_bytes()).hexdigest() != checksums.get(name):
            raise ValueError('安装包校验失败')
        staging = directory/'unpacked'
        staging.mkdir()
        with tarfile.open(directory/name) as archive:
            for member in validate_archive(archive):
                # 文件名已限定为五个固定普通文件，不使用可接受外部路径的解包方式。
                source = archive.extractfile(member)
                with (staging/member.name).open('wb') as target:
                    shutil.copyfileobj(source, target)
        for binary in ('nexo-server', 'caddy'):
            (staging/binary).chmod(0o755)
        result = subprocess.run([str(staging/'nexo-server'), '--version'], check=True, capture_output=True, text=True, timeout=10)
        if result.stdout.strip().split()[-1] != version:
            raise ValueError('安装包程序版本不匹配')
        staging.rename(destination)
    return destination


def select(directory):
    if directory.parent != ROOT/'releases' or directory.is_symlink() or not directory.is_dir():
        raise ValueError('版本路径不在受管目录')
    link = ROOT/'next'
    link.unlink(missing_ok=True)
    link.symlink_to(directory)
    os.replace(link, ROOT/'current')


def restart():
    subprocess.run(['systemctl', 'restart', 'nexo-node.service'], check=True, timeout=30)


def probe():
    try:
        with urllib.request.urlopen('http://127.0.0.1:8282/health', timeout=2) as response:
            if response.status == 200:
                return json.loads(response.read(16384))
    except (OSError, ValueError):
        pass
    return {}


def healthy(version, previous_instance=None):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = probe()
        if status.get('version') == version and status.get('instance') and status['instance'] != previous_instance:
            return True
        time.sleep(2)
    return False


def finish_install(task, previous, recovering=False):
    # root 拥有的日志先于程序切换持久化；助手重启只核对、回退，不重复安装命令。
    old = ROOT/'releases'/previous['previous_version']
    target = ROOT/'releases'/previous['target_version']
    details = {key: previous[key] for key in ('previous_version', 'target_version', 'previous_instance', 'action')}
    try:
        if not recovering:
            if previous['action'] == 'install':
                select(target)
            restart()
        if (ROOT/'current').resolve(strict=True) != target or not healthy(target.name, previous['previous_instance']):
            raise RuntimeError('新进程未在 60 秒内恢复目标版本、管理连接和健康检查')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        try:
            select(old)
            restart()
            if not healthy(old.name):
                raise RuntimeError('旧版本也未恢复健康')
            write_status(task, 'rolled_back', str(error), **details)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as rollback:
            write_status(task, 'rollback_failed', str(rollback), **details)
        return
    write_status(task, 'installed', **details)


def main():
    task = 'unknown'
    try:
        previous = read_json(STATE/'status.json') if (STATE/'status.json').exists() else {}
        if previous.get('stage') == 'installing':
            finish_install(previous['task_id'], previous, recovering=True)
            return
        request = read_json(STATE/'inbox/request.json')
        task, action, version = request['task_id'], request['action'], request['version']
        if not isinstance(task, str) or not TASK.fullmatch(task) or not isinstance(version, str) or not VERSION.fullmatch(version):
            raise ValueError('任务或版本格式无效')
        if action not in ('prepare', 'install', 'restart'):
            raise ValueError('不支持的维护操作')
        if previous.get('task_id') == task and previous.get('stage') in ('installed', 'failed', 'rolled_back', 'rollback_failed'):
            return
        if action == 'prepare':
            if previous.get('task_id') == task and previous.get('stage') == 'downloaded':
                if previous.get('target_version') != version:
                    raise ValueError('同一任务不能变更目标版本')
                return
            write_status(task, 'downloading', target_version=version)
            prepare(version)
            write_status(task, 'downloaded', target_version=version)
            return
        if action == 'install' and (previous.get('task_id') != task or previous.get('stage') != 'downloaded' or previous.get('target_version') != version):
            raise ValueError('安装前必须成功下载并校验当前任务的目标版本安装包')
        old = (ROOT/'current').resolve(strict=True)
        if old.parent != ROOT/'releases' or not VERSION.fullmatch(old.name):
            raise ValueError('当前版本不在受管目录')
        if action == 'restart' and old.name != version:
            raise ValueError('重启不能变更版本')
        details = dict(previous_version=old.name, target_version=version, previous_instance=probe().get('instance'), action=action)
        write_status(task, 'installing', **details)
        finish_install(task, details)
    except Exception as error:
        write_status(task, 'failed', str(error))


if __name__ == '__main__':
    main()
