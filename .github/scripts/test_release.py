import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release


class ReleaseTests(unittest.TestCase):
    version = "0.2.27"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dist = Path(temporary.name)

    def test_scope_and_asset_names(self):
        for components, images, count in (
            (["server"], ["server"], 1),
            (["agent"], ["agent"], 1),
            (["node"], [], 2),
            (["server", "agent", "node"], ["server", "agent"], 3),
        ):
            with self.subTest(components=components):
                manifest = {
                    "version": self.version,
                    "node_version": self.version if "node" in components else "0.2.24",
                    "components": components,
                }
                self.assertEqual(
                    release.resolve_scope(f"v{self.version}", self.version, self.version, manifest),
                    (self.version, components, "node" in components, images),
                )
                names = release.archive_names(self.version, components)
                self.assertEqual(len(names), count)
                self.assertEqual(any(name.endswith("-docker.tar.gz") for name in names), bool(images))

    def test_bad_release_scope_fails_before_any_build(self):
        manifest = {"version": self.version, "node_version": "0.2.24", "components": ["node"]}
        for change in ({}, {"components": []}, {"components": ["server", "server"]}, {"components": ["other"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                release.resolve_scope(f"v{self.version}", self.version, self.version, manifest | change)
        with self.assertRaisesRegex(ValueError, "版本不一致"):
            release.resolve_scope(f"v{self.version}", "0.2.26", self.version, manifest)

    def test_partial_draft_reuses_uploaded_file_and_uploads_sums_last(self):
        assets = release.archive_names(self.version, ["node"])
        for name in assets:
            (self.dist / name).write_bytes(b"new")
        calls = []

        def gh(*args, **kwargs):
            calls.append(args)
            if args[1] == "download":
                (Path(args[-1]) / args[-3]).write_bytes(b"existing")

        draft = {"isDraft": True, "assets": [{"name": assets[0]}]}
        with patch.object(release, "read_release", return_value=draft), patch.object(release, "gh", side_effect=gh):
            release.publish(self.version, ["node"], self.dist)

        tag = f"v{self.version}"
        self.assertEqual((self.dist / assets[0]).read_bytes(), b"existing")
        self.assertEqual(calls[1:], [
            ("release", "upload", tag, str(self.dist / assets[1])),
            ("release", "upload", tag, str(self.dist / "SHA256SUMS")),
            ("release", "edit", tag, "--draft=false"),
        ])
        self.assertEqual((self.dist / "SHA256SUMS").read_text(), release.checksums(self.dist, assets))

    def test_published_release_only_downloads_and_checks(self):
        asset, = release.archive_names(self.version, ["agent"])
        (self.dist / asset).write_bytes(b"original")
        sums = release.checksums(self.dist, [asset])
        published = {"isDraft": False, "assets": [{"name": asset}, {"name": "SHA256SUMS"}]}

        def download(*args, **kwargs):
            self.assertEqual(args[:2], ("release", "download"))
            filename = args[-3]
            (Path(args[-1]) / filename).write_bytes(sums.encode() if filename == "SHA256SUMS" else data)

        for data in (b"original", b"damaged"):
            with patch.object(release, "read_release", return_value=published), patch.object(release, "gh", side_effect=download):
                if data == b"original":
                    release.publish(self.version, ["agent"], self.dist)
                else:
                    with self.assertRaisesRegex(ValueError, "既有资产校验失败"):
                        release.publish(self.version, ["agent"], self.dist)

    def test_release_query_error_is_not_treated_as_missing(self):
        with patch.object(release, "gh", side_effect=subprocess.CalledProcessError(1, "gh", stderr="HTTP 503")):
            with self.assertRaisesRegex(ValueError, "HTTP 503"):
                release.read_release("v0.2.27")


if __name__ == "__main__":
    unittest.main()
