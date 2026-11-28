from pathlib import Path
import copy
import importlib.util
import json
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SDK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK / "tools"))
import keyless_gate as G

spec = importlib.util.spec_from_file_location("keyless_sdk_build", SDK / "build.py")
B = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = B
spec.loader.exec_module(B)


class KeylessDeliveryGateTests(unittest.TestCase):
    def migration(self):
        return dict(scope="full", expected_members=1, deferred_idx=[],
            members=[dict(idx=0, name="api.o", status="FAIL", layout=dict(ref="elf", new="elf"),
                          problems=["T missing 1", "T extra 1"])],
            problems=["api.o: T missing 1", "api.o: T extra 1"])

    def test_deliberate_tu_migration_keeps_other_errors_fatal(self):
        gate = self.migration()
        self.assertEqual([], G.structural_problems(gate))
        for problem in ("ordinal sequence differs", "api.o: llvm-nm failed: fixture", "member extra: fixture"):
            changed = copy.deepcopy(gate)
            changed["problems"].append(problem)
            self.assertIn(problem, G.structural_problems(changed))
        changed = copy.deepcopy(gate)
        changed["members"][0]["layout"]["new"] = "bitcode"
        self.assertTrue(G.structural_problems(changed))

    def test_exact_retired_apis_fail_without_rejecting_business_keys(self):
        required = ["maplesu::sdk::get_root()", "maplesu::sdk::run_root_cmd(char const*, std::string&)",
                    "maplesu::sdk::get_all_modules_with_cb(void (*)(module_record const*))"]
        self.assertEqual([], G.retired_api_problems(["business_key"], required, required))
        problems = G.retired_api_problems(list(G.RETIRED_SYMBOLS),
            ["skroot_env::get_root(char const*)", "maplesu::sdk::run_root_cmd(char const*, char const*, std::string&)"], required)
        self.assertEqual(10, len(problems))

    def test_explicit_legacy_tls_keeps_keyless_consumer_independent(self):
        legacy = ["__set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW",
                  "__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW"]
        current = ["maplesu::sdk::get_root()"]
        self.assertEqual([], G.retired_api_problems(legacy, current, current))
        self.assertEqual([], G.legacy_credential_problems([]))
        self.assertEqual(2, len(G.legacy_credential_problems(legacy)))

    def test_module_macros_select_actual_keyless_symbols(self):
        header = (SDK.parent / "include/maplesu/compat/native_module_abi.h").read_text(encoding="utf-8")
        symbols = G.module_entry_symbols(header)
        self.assertEqual(7, len(set(symbols)))
        self.assertEqual(4, sum(name.endswith("_keyless_v1") for name in symbols))

    def entries(self):
        entries = []
        for path in sorted((SDK / "manifest").glob("*.json")):
            if not path.name[:4].isdigit():
                continue
            row = json.loads(path.read_text(encoding="utf-8-sig"))
            entries.append(B.ManifestEntry(idx=row["idx"], name=row["name"],
                sources=[B.resolve_source(item) for item in row.get("sources", [])],
                source_raw=row.get("sources", []), flags_profile=row["flagsProfile"],
                status=row["status"], layout=row["layout"]))
        return entries

    def test_active_api_members_all_select_current_source(self):
        result = B.validate_keyless_sources(self.entries())
        self.assertTrue(result)

    def test_complete_source_build_selects_current_links(self):
        source = B.parse_args(["--all", "--source-selection", "fixture.json"])
        selected = B._select_stages(source)
        self.assertTrue(selected["pack"] and selected["gate"])
        self.assertFalse(selected["link_sample"] or selected["verify"])
        reference = B._select_stages(B.parse_args(["--all", "--reference-payloads"]))
        self.assertTrue(reference["link_sample"] and reference["verify"])

    def test_vendor_missing_and_ir_fallback_are_rejected(self):
        for kind in ("vendor", "missing", "ir"):
            entries = self.entries()
            entry = next(item for item in entries if item.idx == 23)
            if kind == "vendor":
                entry.status = B.S.STATUS_VENDOR_COPY
            elif kind == "missing":
                entry.sources = []
            else:
                entry.sources = [SDK / "legacy.bc"]
            with self.assertRaises(B.StageError):
                B.validate_keyless_sources(entries)

    def explicit_contract(self):
        return json.loads((SDK / "tools/explicit_legacy_abi.json").read_text(encoding="utf-8"))

    def explicit_measurements(self):
        contract = self.explicit_contract()
        symbols = [row["symbol"] for row in contract["symbols"]]
        definitions = [dict(symbol=symbol, kind="T") for symbol in symbols]
        return dict(archive_providers={symbol: [dict(member="maplesu_installer.o", kind="T")]
                                      for symbol in symbols},
                    adapter_definitions={abi: copy.deepcopy(definitions) for abi in ("arm64", "armv7")},
                    consumer_references={abi: dict(original=symbols[:], current=symbols[:])
                                         for abi in ("arm64", "armv7")},
                    symbol_signatures={row["symbol"]: row["signature"] for row in contract["symbols"]},
                    keyless_required=["_ZN7maplesu3sdk8get_rootEv"])

    def test_explicit_contract_requires_measured_source_and_exact_abi(self):
        self.assertEqual([], G.explicit_legacy_abi_problems(self.explicit_contract(), **self.explicit_measurements()))
        for field, value in (("provider_source", "sdk/src/other.cpp"),
                             ("provider_member", dict(idx=60, name="maplesu_root.o")),
                             ("historical_include", "include"),
                             ("consumer_source", "sdk/tools/keyless_public_abi.cpp")):
            contract = self.explicit_contract()
            contract[field] = value
            self.assertTrue(G.explicit_legacy_abi_problems(contract, **self.explicit_measurements()))
        contract = self.explicit_contract()
        contract["symbols"][0] = contract["symbols"][1]
        self.assertTrue(G.explicit_legacy_abi_problems(contract, **self.explicit_measurements()))

    def test_explicit_wrong_duplicate_missing_weak_or_unknown_exports_fail(self):
        contract = self.explicit_contract()
        symbol = contract["symbols"][0]["symbol"]
        for mutation in ("member", "duplicate", "missing", "weak", "extra"):
            measured = self.explicit_measurements()
            providers = measured["archive_providers"]
            if mutation == "member":
                providers[symbol][0]["member"] = "maplesu_root.o"
            elif mutation == "duplicate":
                providers[symbol].append(dict(member="maplesu_root.o", kind="T"))
            elif mutation == "missing":
                providers[symbol] = []
            elif mutation == "weak":
                providers[symbol][0]["kind"] = "W"
            else:
                providers["_ZN10skroot_env15unknown_old_apiEPKc"] = [dict(member="maplesu_installer.o", kind="T")]
            self.assertTrue(G.explicit_legacy_abi_problems(contract, **measured), mutation)

    def test_explicit_both_architectures_and_original_consumers_remain_required(self):
        contract = self.explicit_contract()
        for mutation in ("abi", "extra", "wrong_signature", "original", "current", "credential"):
            measured = self.explicit_measurements()
            if mutation == "abi":
                del measured["adapter_definitions"]["armv7"]
            elif mutation == "extra":
                measured["adapter_definitions"]["arm64"].append(dict(symbol="unknown_old_api", kind="T"))
            elif mutation == "wrong_signature":
                measured["symbol_signatures"][contract["symbols"][0]["symbol"]] += " const"
            elif mutation in ("original", "current"):
                measured["consumer_references"]["armv7"][mutation].pop()
            else:
                measured["keyless_required"].append(contract["symbols"][0]["symbol"])
            self.assertTrue(G.explicit_legacy_abi_problems(contract, **measured), mutation)

    def test_archive_retired_check_accepts_only_explicit_exact_pairs(self):
        contract = self.explicit_contract()
        approved = {row["symbol"]: row["signature"] for row in contract["symbols"]}
        raw, signatures = list(approved), list(approved.values())
        required = ["maplesu::sdk::get_root()", "maplesu::sdk::run_root_cmd(char const*, std::string&)"]
        self.assertTrue(G.retired_api_problems(raw, signatures, required))
        self.assertEqual([], G.retired_api_problems(raw, signatures, required, explicit_legacy=approved))
        self.assertTrue(G.retired_api_problems(raw + ["unknown_old_api"],
            signatures + ["skroot_env::get_root(char const*, int)"], required, explicit_legacy=approved))
        self.assertTrue(G.retired_api_problems(raw, signatures[:-1], required, explicit_legacy=approved))

    def test_archive_provenance_parser_keeps_duplicate_definitions(self):
        contract = self.explicit_contract()
        symbol = contract["symbols"][0]["symbol"]
        parsed = G.archive_legacy_providers(
            "D:/archive.a[maplesu_installer.o]: " + symbol + " T 0 4\n" +
            "D:/archive.a[maplesu_root.o]: " + symbol + " W 0 4\n", contract)
        self.assertEqual([dict(member="maplesu_installer.o", kind="T"),
                          dict(member="maplesu_root.o", kind="W")], parsed[symbol])
        with self.assertRaises(ValueError):
            G.archive_legacy_providers("malformed symbol provenance", contract)

    def test_explicit_contract_drift_keeps_original_identity_and_fails(self):
        contract = self.explicit_contract()
        with tempfile.TemporaryDirectory(dir=SDK) as temporary:
            root = Path(temporary)
            tools, link, report = root / "tools", root / "link", root / "report"
            for directory in (tools, link, report):
                directory.mkdir()
            contract_path = tools / "explicit_legacy_abi.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            original = B.P.file_record(contract_path, root)
            for source in (root / G.EXPLICIT_LEGACY_SOURCE, tools / "explicit_legacy_public_abi.cpp"):
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("// fixture", encoding="utf-8")
            manifest = root / "manifest.jsonl"
            manifest.write_text("", encoding="utf-8")
            archive = root / "archive.a"
            archive.write_bytes(b"fixture")
            changed = False

            def run(stage, name, argv, log, code):
                nonlocal changed
                if not changed:
                    contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
                    changed = True
                if "-o" in argv:
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"object")
                if "-A" in argv:
                    output = "".join("archive.a[maplesu_installer.o]: " + row["symbol"] + " T 0 4\n"
                                     for row in contract["symbols"])
                else:
                    kind = "T" if name.endswith("-adapter-nm") else "U"
                    output = "".join(row["symbol"] + " " + kind + " 0 4\n" for row in contract["symbols"])
                return SimpleNamespace(stdout=output)

            with patch.multiple(B, TOOLS_DIR=tools, MAPLESU_SDK_ROOT=root, LINK_DIR=link,
                                REPORT_DIR=report, ARCHIVE_OUT=archive), \
                    patch.object(B.S, "REPO_ROOT", root), \
                    patch.object(B.S, "read_archive", return_value=SimpleNamespace(members=[])), \
                    patch.object(B, "run_checked", side_effect=run), \
                    patch.object(B.P, "precompile_snapshot", return_value={}), \
                    patch.object(B.P, "dependency_receipt", return_value={}):
                result = B.stage_explicit_legacy_abi(SimpleNamespace(tool=lambda name: root / name), {}, [], manifest,
                    {row["symbol"]: row["signature"] for row in contract["symbols"]})
            self.assertEqual(original, result["contract"])
            self.assertIn("explicit legacy ABI contract changed during validation", result["problems"])
            self.assertEqual("FAIL", result["status"])

    def test_keyless_approval_uses_only_already_validated_signatures(self):
        approved = {row["symbol"]: row["signature"] for row in self.explicit_contract()["symbols"]}
        explicit = dict(problems=[], symbol_signatures=approved,
                        contract=dict(path="unvalidated-second-read.json", size=0, sha256="fixture"))
        with tempfile.TemporaryDirectory(dir=SDK) as temporary:
            root = Path(temporary)
            tools, link, report, include = root / "tools", root / "link", root / "report", root / "include"
            for directory in (tools, link, report, include / "maplesu/compat"):
                directory.mkdir(parents=True)
            for path in (tools / "keyless_public_abi.cpp", root / "archive.a", root / "llvm-cxxfilt",
                         include / "maplesu/compat/native_module_abi.h"):
                path.write_bytes(b"fixture")

            def run(stage, name, argv, log, code):
                Path(argv[argv.index("-o") + 1]).write_bytes(b"object")

            symbols = SimpleNamespace(defined=set(), undefined=set(), weak_defined=set(), weak_undefined=set())
            with patch.multiple(B, TOOLS_DIR=tools, LINK_DIR=link, REPORT_DIR=report,
                                INCLUDE_DIR=include, ARCHIVE_OUT=root / "archive.a"), \
                    patch.object(B.S, "REPO_ROOT", root), \
                    patch.object(B, "run_checked", side_effect=run), \
                    patch.object(B, "stage_explicit_legacy_abi", return_value=explicit), \
                    patch.object(B.S, "nm_symbols", return_value=symbols), \
                    patch.object(B.P, "snapshot_inputs", return_value=[]), \
                    patch.object(B.P, "precompile_snapshot", return_value={}), \
                    patch.object(B.P, "dependency_receipt", return_value={}), \
                    patch.object(B.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")), \
                    patch.object(G, "module_entry_symbols", return_value=[]), \
                    patch.object(G, "retired_api_problems", return_value=[]) as retired:
                result = B.stage_keyless_public_abi(SimpleNamespace(tool=lambda name: root / name), {})
            self.assertIs(approved, retired.call_args.kwargs["explicit_legacy"])
            self.assertEqual("PASS", result["status"])


if __name__ == "__main__":
    unittest.main()
