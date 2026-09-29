"""更新助手故障验收：所有路径及 systemd 操作均隔离在临时目录，不操作宿主机服务。"""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('node_updater', Path(__file__).with_name('node-updater.py'))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)/'install'
        self.state = Path(self.directory.name)/'update'
        (self.root/'releases'/'0.2.10').mkdir(parents=True)
        (self.root/'releases'/'0.2.11').mkdir()
        (self.root/'current').symlink_to(self.root/'releases'/'0.2.10', target_is_directory=True)
        (self.state/'inbox').mkdir(parents=True)
        self.paths = patch.multiple(updater, ROOT=self.root, STATE=self.state)
        self.paths.start()
        self.addCleanup(self.paths.stop)
        self.addCleanup(self.directory.cleanup)
        self.probe = patch.object(updater, 'probe', return_value={'version': '0.2.10', 'instance': 'old-process'})
        self.probe.start()
        self.addCleanup(self.probe.stop)

    def request(self, action, version='0.2.11', task='test-1'):
        (self.state/'inbox'/'request.json').write_text(json.dumps(dict(task_id=task, action=action, version=version)))

    def result(self):
        return json.loads((self.state/'status.json').read_text())

    def downloaded(self):
        updater.write_status('test-1', 'downloaded', target_version='0.2.11')

    def test_install_success_and_duplicate_do_not_restart_twice(self):
        self.request('install')
        self.downloaded()
        with patch.object(updater, 'restart') as restart, patch.object(updater, 'healthy', return_value=True):
            updater.main()
            updater.main()
        self.assertEqual(restart.call_count, 1)
        self.assertEqual(self.result()['stage'], 'installed')
        self.assertEqual((self.root/'current').resolve().name, '0.2.11')

    def test_startup_failure_rolls_back_and_rollback_failure_is_distinct(self):
        for recovery, expected in [(True, 'rolled_back'), (False, 'rollback_failed')]:
            self.request('install')
            self.downloaded()
            with patch.object(updater, 'restart'), patch.object(updater, 'healthy', side_effect=[False, recovery]):
                updater.main()
            self.assertEqual(self.result()['stage'], expected)
            self.assertEqual((self.root/'current').resolve().name, '0.2.10')

    def test_no_prepare_and_malformed_request_never_restart(self):
        with patch.object(updater, 'restart') as restart:
            for action, version in [('install', '0.2.11'), ('shell', '0.2.11'), ('prepare', '../../tmp'), ('prepare', '1.2.3-beta')]:
                self.request(action, version)
                updater.main()
                self.assertEqual(self.result()['stage'], 'failed')
            restart.assert_not_called()

    def test_download_disk_and_architecture_errors_leave_current_untouched(self):
        self.request('prepare')
        for error in [OSError('下载中断'), OSError('磁盘不足'), ValueError('架构错误')]:
            with patch.object(updater, 'prepare', side_effect=error), patch.object(updater, 'restart') as restart:
                updater.main()
                self.assertEqual(self.result()['stage'], 'failed')
                restart.assert_not_called()
            self.assertEqual((self.root/'current').resolve().name, '0.2.10')

    def test_request_reader_rejects_symlink_fifo_directory_and_oversize(self):
        path = self.state/'inbox'/'unsafe'
        for kind in ('symlink', 'fifo', 'directory', 'oversize'):
            if kind == 'symlink':
                path.symlink_to('/etc/passwd')
            elif kind == 'fifo':
                os.mkfifo(path)
            elif kind == 'directory':
                path.mkdir()
            else:
                path.write_bytes(b' ' * 16385)
            with self.assertRaises((OSError, ValueError)):
                updater.read_json(path)
            path.rmdir() if kind == 'directory' else path.unlink()

    def test_prepared_version_cannot_be_changed_before_install(self):
        self.downloaded()
        self.request('install', '0.2.10')
        with patch.object(updater, 'restart') as restart:
            updater.main()
            restart.assert_not_called()
        self.assertEqual(self.result()['stage'], 'failed')

    def test_helper_recovery_checks_actual_process_without_replaying_install(self):
        updater.write_status('test-1', 'installing', previous_version='0.2.10', target_version='0.2.11', previous_instance='old-process', action='install')
        updater.select(self.root/'releases'/'0.2.11')
        self.request('install')
        with patch.object(updater, 'restart') as restart, patch.object(updater, 'healthy', return_value=True) as healthy:
            updater.main()
            updater.main()
            restart.assert_not_called()
            healthy.assert_called_once_with('0.2.11', 'old-process')
        self.assertEqual(self.result()['stage'], 'installed')

    def test_crash_before_switch_rolls_back_instead_of_reinstalling(self):
        updater.write_status('test-1', 'installing', previous_version='0.2.10', target_version='0.2.11', previous_instance='old-process', action='install')
        with patch.object(updater, 'restart') as restart, patch.object(updater, 'healthy', return_value=True):
            updater.main()
            restart.assert_called_once()
        self.assertEqual(self.result()['stage'], 'rolled_back')
        self.assertEqual((self.root/'current').resolve().name, '0.2.10')

    def test_archive_rejects_path_traversal_links_and_missing_files(self):
        for unsafe in ['../nexo-server', 'symlink', 'missing']:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                for filename in updater.FILES:
                    if unsafe == 'missing' and filename == 'caddy':
                        continue
                    member = tarfile.TarInfo('../nexo-server' if unsafe.startswith('../') and filename == 'nexo-server' else filename)
                    if unsafe == 'symlink' and filename == 'caddy':
                        member.type = tarfile.SYMTYPE
                        member.linkname = '/bin/sh'
                    archive.addfile(member)
            buffer.seek(0)
            with tarfile.open(fileobj=buffer) as archive, self.assertRaises(ValueError):
                updater.validate_archive(archive)


if __name__ == '__main__':
    unittest.main()
