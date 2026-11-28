"""Exercise the production support exporter with actual AArch64 support ELFs."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
PARSER = argparse.ArgumentParser()
PARSER.add_argument("--builder", type=Path, default=ROOT / "scripts/build-ultra-manager-claim.py")
PARSER.add_argument("--build", type=Path, help="new directory preserving compiler logs and receipts")
ARGS, UNITTEST_ARGS = PARSER.parse_known_args()
FACTS = [1, 4, 56, 52, 8, 5, 96, 56, 88, 24]
SOURCE_SYMBOLS = {
    "materializer": "msu_manager_claim_materialize_source",
    "bootstrap": "msu_manager_resident_boot_deployment_source",
}


def function_offset(path, name):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        symbol, = elf.get_section_by_name(".symtab").get_symbol_by_name(name)
        return symbol["st_value"] - elf.get_section_by_name(".text")["sh_addr"]


class SourceSupportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ARGS.build:
            cls.directory = ARGS.build.resolve()
            cls.directory.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".tmp", prefix="source-support-")
            cls.directory = Path(cls.temporary.name)
        spec = importlib.util.spec_from_file_location("claim_source_support_test", ARGS.builder)
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)
        # The standalone support build uses the production current-source list.
        groups, _, _ = cls.builder.current_sources.selected_inputs(cls.builder)
        cls.builder.SUPPORT_SOURCES = groups["support"]
        cls.report = cls.builder.build_support(cls.directory / "actual")
        cls.support = cls.directory / "actual/support"
        (cls.directory / "support-report.json").write_text(
            json.dumps(cls.report, indent=2) + "\n", encoding="utf-8", newline="\n")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def metadata(self, component, data=None, facts=None, binary=None):
        if data is None:
            data = (self.support / (component + ".elf")).read_bytes()
        if binary is None:
            binary = (self.support / (component + ".bin")).read_bytes()
        return self.builder.support_source_metadata(ELFFile(io.BytesIO(data)), binary,
            FACTS if facts is None else facts, component)

    def symbol_fixture(self, component):
        data = bytearray((self.support / (component + ".elf")).read_bytes())
        elf = ELFFile(io.BytesIO(data))
        table = elf.get_section_by_name(".symtab")
        index, = [index for index, symbol in enumerate(table.iter_symbols())
                  if symbol.name == SOURCE_SYMBOLS[component]]
        return data, elf, table["sh_offset"] + index * table["sh_entsize"]

    def test_actual_build_exports_paired_source_entries(self):
        loader = self.report["materializer"]
        boot = self.report["bootstrap"]
        self.assertEqual(3, loader["protocolVersion"])
        self.assertEqual(0, loader["entryOffset"])
        self.assertEqual(4, boot["deploymentAnchorVersion"])
        self.assertEqual(48, boot["deploymentConfigBytes"])
        for field, value in {
            "sourceEntryOffset": function_offset(self.support / "materializer.elf",
                "msu_manager_claim_materialize_source"),
            "sourceProtocolVersion": 4, "sourceHeaderBytes": 56,
            "sourceBytesOffset": 52, "sourceChunkBytes": 8,
        }.items():
            with self.subTest(component="materializer", field=field):
                self.assertIn(field, loader, "SOURCE_MATERIALIZER_EXPORT_MISSING")
                self.assertEqual(value, loader[field])
        for field, value in {
            "deploymentSourceBootEntryOffset": function_offset(self.support / "bootstrap.elf",
                "msu_manager_resident_boot_deployment_source"),
            "sourceAnchorVersion": 5, "sourceAnchorBytes": 96,
            "sourceBindingBytes": 56, "sourceConfigBytes": 88, "sourceRecordBytes": 24,
        }.items():
            with self.subTest(component="bootstrap", field=field):
                self.assertIn(field, boot, "SOURCE_BOOT_EXPORT_MISSING")
                self.assertEqual(value, boot[field])

    def test_probe_source_and_actual_target_object_are_bound_by_receipt(self):
        receipt = json.loads((self.support / "source-inputs.json").read_text())
        for kind, name in (("source", "source-abi.c"), ("object", "source-abi.o")):
            self.assertEqual(self.builder.identity(self.support / name), receipt["abiProbe"][kind])
        self.assertEqual(FACTS, self.builder.object_words(self.support / "source-abi.o",
            "msu_support_source_facts"))
        for component in SOURCE_SYMBOLS:
            with (self.support / (component + ".elf")).open("rb") as stream:
                self.assertIsNone(ELFFile(stream).get_section_by_name(".symtab").get_symbol_by_name(
                    "msu_support_source_facts"), "ABI probe must stay outside runtime support")

    def test_legacy_absence_requires_both_compiled_capability_and_source_symbol_absent(self):
        for component in SOURCE_SYMBOLS:
            data, _, at = self.symbol_fixture(component)
            struct.pack_into("<I", data, at, 0)
            with self.subTest(component=component, case="complete-absence"):
                self.assertEqual({}, self.metadata(component, data=data, facts=[0]))
            for case, fixture, facts in (("symbol-only", None, [0]),
                                          ("facts-only", data, FACTS)):
                with self.subTest(component=component, case=case), self.assertRaisesRegex(
                        ValueError, "Partial/unsupported"):
                    self.metadata(component, data=fixture, facts=facts)

    def test_partial_or_incompatible_compiled_layouts_are_rejected(self):
        wrong_config = [*FACTS[:8], 48, FACTS[9]]
        for component in SOURCE_SYMBOLS:
            for facts in ([], FACTS[:-1], [0, *FACTS[1:]], wrong_config,
                          [1, 3, *FACTS[2:]], [*FACTS, 0]):
                with self.subTest(component=component, facts=facts), self.assertRaisesRegex(
                        ValueError, "Partial/unsupported"):
                    self.metadata(component, facts=facts)

    def test_malformed_actual_source_symbols_are_rejected(self):
        for component in SOURCE_SYMBOLS:
            original, elf, at = self.symbol_fixture(component)
            size = (self.support / (component + ".bin")).stat().st_size
            source_offset = function_offset(self.support / (component + ".elf"), SOURCE_SYMBOLS[component])
            changes = {
                "missing": (0, "<I", 0), "not-function": (4, "B", 0x10),
                "not-global": (4, "B", 0x02), "undefined": (6, "<H", 0),
                "misaligned-entry": (8, "<Q", source_offset + 2),
                "empty-function": (16, "<Q", 0), "unaligned-size": (16, "<Q", 5),
                "out-of-range": (16, "<Q", size + 4), "legacy-alias": (8, "<Q", 0),
            }
            for case, (relative, encoding, value) in changes.items():
                changed = bytearray(original)
                struct.pack_into(encoding, changed, at + relative, value)
                with self.subTest(component=component, case=case), self.assertRaises(ValueError):
                    self.metadata(component, data=changed)
            duplicate = bytearray(original)
            table = elf.get_section_by_name(".symtab")
            other = next(index for index, symbol in enumerate(table.iter_symbols())
                         if symbol.name and symbol.name != SOURCE_SYMBOLS[component])
            other_at = table["sh_offset"] + other * table["sh_entsize"]
            duplicate[other_at:other_at + table["sh_entsize"]] = original[at:at + table["sh_entsize"]]
            with self.subTest(component=component, case="duplicate"), self.assertRaisesRegex(
                    ValueError, "Missing/ambiguous"):
                self.metadata(component, data=duplicate)
            nonexec = bytearray(original)
            flags_at = elf["e_shoff"] + elf.get_section_index(".text") * elf["e_shentsize"] + 8
            struct.pack_into("<Q", nonexec, flags_at, elf.get_section_by_name(".text")["sh_flags"] & ~4)
            with self.subTest(component=component, case="non-executable"), self.assertRaises(ValueError):
                self.metadata(component, data=nonexec)
            wrong_target = bytearray(original)
            struct.pack_into("<H", wrong_target, 18, 62)
            with self.subTest(component=component, case="wrong-target"), self.assertRaises(ValueError):
                self.metadata(component, data=wrong_target)
            binary = bytearray((self.support / (component + ".bin")).read_bytes())
            binary[0] ^= 1
            with self.subTest(component=component, case="unpaired-bytes"), self.assertRaises(ValueError):
                self.metadata(component, binary=binary)

    def test_source_boot_cannot_alias_either_legacy_boot_abi(self):
        for field in ("bootEntryOffset", "deploymentBootEntryOffset"):
            data, _, at = self.symbol_fixture("bootstrap")
            struct.pack_into("<Q", data, at + 8, self.report["bootstrap"][field])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "aliases"):
                self.metadata("bootstrap", data=data)

    def test_bootstrap_only_rebuild_keeps_complete_source_metadata(self):
        report = self.builder.build_support(self.directory / "bootstrap-only", bootstrap_only=True)
        self.assertEqual({"bootstrap"}, set(report))
        for field in ("bytes", "sha256", "bootEntryOffset", "deploymentBootEntryOffset",
                      "deploymentSourceBootEntryOffset", "sourceAnchorVersion", "sourceAnchorBytes",
                      "sourceBindingBytes", "sourceConfigBytes", "sourceRecordBytes"):
            with self.subTest(field=field):
                self.assertEqual(self.report["bootstrap"][field], report["bootstrap"][field])
        (self.directory / "bootstrap-only-report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

    def test_actual_compiler_rejects_partial_macros_and_wrong_source_function_abi(self):
        negative = self.directory / "negative-abi"
        negative.mkdir()
        kernel = Path("source/runtime/ultra/identity/kernel")
        mutations = {
            "partial-macros": ("manager_claim_loader.h", "#define MSU_LOADER_SOURCE_VERSION 4U",
                               "", "Partial source support ABI"),
            "materializer-type": ("manager_claim_loader.h", "msu_loader_u32 capacity);\n\n#endif",
                                  "msu_loader_u64 capacity);\n\n#endif", "source materializer function ABI"),
            "boot-type": ("manager_claim_bootstrap.h", "const void *source_base, msu_loader_u32 source_bytes);",
                          "const void *source_base, msu_loader_u64 source_bytes);", "source boot function ABI"),
        }
        results = {}
        for case, (header, before, after, message) in mutations.items():
            fixture = negative / case
            shutil.copytree(self.support / "source", fixture / "source")
            path = fixture / kernel / header
            text = path.read_text()
            self.assertEqual(1, text.count(before), case)
            path.write_text(text.replace(before, after), encoding="utf-8", newline="\n")
            (fixture / "source-abi.c").write_text(self.builder.support_source_probe(),
                encoding="utf-8", newline="\n")
            command = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--mount", f"type=bind,source={fixture},target=/fixture",
                "ghcr.io/ylarod/ddk-min:android16-6.12-20260828", "clang", "--target=aarch64-none-elf",
                "-Os", "-ffreestanding", "-Wall", "-Wextra", "-Werror", "-c", "/fixture/source-abi.c",
                "-o", "/fixture/source-abi.o"]
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30)
            (fixture / "build.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            results[case] = {"command": command, "exitCode": result.returncode}
            with self.subTest(case=case):
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stderr)
        (negative / "results.json").write_text(json.dumps(results, indent=2) + "\n",
            encoding="utf-8", newline="\n")


if __name__ == "__main__":
    unittest.main(argv=[__file__, *UNITTEST_ARGS])
