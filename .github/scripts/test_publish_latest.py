"""覆盖标签倒退、预发布与 manifest 原样复制；无需远端凭据。"""

import unittest
from unittest.mock import Mock, patch

from publish_latest import main, promote, stable_version


class PublishLatestTests(unittest.TestCase):
    def registry(self, tags, current=None):
        registry = Mock()
        registry.tags.return_value = tags
        source = (b'{"manifests": ["amd64", "attestation"]}', "application/vnd.oci.image.index.v1+json", "sha256:source")
        manifests = {tag: source for tag in tags}
        manifests["latest"] = current
        registry.manifest.side_effect = manifests.get
        registry.alias.side_effect = lambda value: manifests.update(latest=value)
        return registry, source

    def test_initial_alias_copies_complete_manifest_and_verifies(self):
        registry, source = self.registry(["0.2.0"])
        self.assertIn("已指向", promote(registry, "0.2.0", True))
        registry.alias.assert_called_once_with(source)
        self.assertEqual(registry.manifest.call_args.args, ("latest",))

    def test_pre_release_does_not_access_registry(self):
        registry = Mock()
        self.assertIn("跳过", promote(registry, "0.3.0-rc.1", True))
        self.assertEqual(registry.mock_calls, [])

    def test_older_patch_does_not_move_latest_back(self):
        registry, _ = self.registry(["0.2.9", "0.2.10", "0.3.0-rc.1"])
        self.assertIn("历史", promote(registry, "0.2.9", True))
        registry.alias.assert_not_called()
        registry.manifest.assert_not_called()

    def test_newest_stable_ignores_newer_pre_release(self):
        registry, source = self.registry(["0.2.9", "0.2.10", "0.3.0-rc.1"])
        promote(registry, "0.2.10", True)
        registry.alias.assert_called_once_with(source)

    def test_dry_run_and_existing_alias_do_not_write(self):
        registry, source = self.registry(["0.2.0"])
        self.assertIn("待将", promote(registry, "0.2.0"))
        registry.alias.assert_not_called()
        registry, _ = self.registry(["0.2.0"], source)
        self.assertIn("已指向", promote(registry, "0.2.0", True))
        registry.alias.assert_not_called()

    def test_missing_image_and_registry_errors_do_not_write(self):
        registry, _ = self.registry([])
        with self.assertRaisesRegex(RuntimeError, "不存在"):
            promote(registry, "0.2.0", True)
        registry.alias.assert_not_called()
        registry.tags.side_effect = RuntimeError("网络不可达")
        with self.assertRaisesRegex(RuntimeError, "网络不可达"):
            promote(registry, "0.2.0", True)
        registry.alias.assert_not_called()

    def test_post_write_digest_mismatch_fails(self):
        registry, _ = self.registry(["0.2.0"])
        registry.alias.side_effect = None
        with self.assertRaisesRegex(RuntimeError, "摘要"):
            promote(registry, "0.2.0", True)

    def test_stable_version(self):
        self.assertGreater(stable_version("0.2.10"), stable_version("0.2.9"))
        for tag in ["latest", "v0.2.0", "0.2.0-beta.1", "01.2.3"]:
            self.assertIsNone(stable_version(tag))

    def test_only_selected_components_are_published(self):
        for components in [["server"], ["agent"], ["server", "agent"]]:
            with self.subTest(components=components), \
                    patch("sys.argv", ["publish_latest.py", "--version", "0.2.0", "--components", *components, "--apply"]), \
                    patch.dict("os.environ", {"GH_TOKEN": "test-token", "GITHUB_ACTOR": "test-user"}), \
                    patch("publish_latest.Registry") as registry, \
                    patch("publish_latest.promote", return_value="完成") as publish, \
                    patch("builtins.print"):
                main()
                self.assertEqual([call.args[0] for call in registry.call_args_list], [f"thelinyue/nexo-{component}" for component in components])
                self.assertEqual(publish.call_count, len(components))

    def test_pre_release_cli_needs_no_credentials(self):
        with patch("sys.argv", ["publish_latest.py", "--version", "0.3.0-rc.1", "--components", "server", "--apply"]), \
                patch("publish_latest.Registry") as registry, \
                patch("publish_latest.subprocess.check_output") as credentials, \
                patch("builtins.print"):
            main()
            registry.assert_not_called()
            credentials.assert_not_called()


if __name__ == "__main__":
    unittest.main()
