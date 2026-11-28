"""Current keyless ABI checks, separate from historical T/U equivalence."""
from __future__ import annotations

import re
import ast


EXPLICIT_LEGACY_SOURCE = "sdk/src/maplesu/compat/keyed_exports_legacy_abi.cpp"
EXPLICIT_LEGACY_MEMBER = {"idx": 53, "name": "maplesu_installer.o"}
EXPLICIT_LEGACY_CONSUMER = "sdk/tools/explicit_legacy_public_abi.cpp"
EXPLICIT_LEGACY_INCLUDE = "maintenance/freeze/freeze-maplesu-pro-5.2.0-su-uid-isolation-20261114-20261114/include"


def explicit_legacy_abi_problems(contract: dict, *, archive_providers: dict,
                                 adapter_definitions: dict, consumer_references: dict,
                                 symbol_signatures: dict, keyless_required) -> list[str]:
    """Check the measured explicit adapter; this never authorizes a keyless dependency."""
    rows = contract.get("symbols") or []
    symbols = [row.get("symbol") for row in rows]
    signatures = [row.get("signature") for row in rows]
    problems = []
    if (contract.get("schema") != "maplesu-sdk-explicit-legacy-contract/1" or
            contract.get("provider_member") != EXPLICIT_LEGACY_MEMBER or
            contract.get("provider_source") != EXPLICIT_LEGACY_SOURCE or
            contract.get("consumer_source") != EXPLICIT_LEGACY_CONSUMER or
            contract.get("historical_include") != EXPLICIT_LEGACY_INCLUDE or
            len(symbols) != 35 or len(set(symbols)) != 35 or
            len(set(signatures)) != 35 or not all(symbols) or not all(signatures)):
        return ["invalid explicit legacy ABI contract"]
    expected = set(symbols)
    if not set(RETIRED_SYMBOLS) <= expected:
        problems.append("explicit legacy ABI contract omits historical exports")
    if set(archive_providers) != expected:
        problems.append("explicit legacy archive provider coverage differs")
    for symbol in symbols:
        if archive_providers.get(symbol) != [{"member": EXPLICIT_LEGACY_MEMBER["name"], "kind": "T"}]:
            problems.append("explicit legacy export requires one strong definition in m053: " + symbol)
    for row in rows:
        if symbol_signatures.get(row["symbol"]) != row["signature"]:
            problems.append("explicit legacy exact signature differs: " + row["symbol"])
    if set(adapter_definitions) != {"arm64", "armv7"} or set(consumer_references) != {"arm64", "armv7"}:
        problems.append("explicit legacy ABI requires both ARM architectures")
    for abi in ("arm64", "armv7"):
        definitions = adapter_definitions.get(abi) or []
        if (len(definitions) != 35 or
                {row.get("symbol") for row in definitions} != expected or
                any(row.get("kind") != "T" for row in definitions)):
            problems.append("explicit legacy adapter strong definitions differ: " + abi)
        references = consumer_references.get(abi) or {}
        if set(references) != {"original", "current"} or any(
                set(references.get(kind) or []) != expected for kind in ("original", "current")):
            problems.append("explicit legacy original/current header references differ: " + abi)
    problems += ["explicit legacy API required by keyless public API: " + symbol
                 for symbol in sorted(expected.intersection(keyless_required))]
    return problems


def archive_legacy_providers(nm_output: str, contract: dict) -> dict:
    """Preserve duplicate archive definitions and their actual member names."""
    result = {row["symbol"]: [] for row in contract["symbols"]}
    for line in nm_output.splitlines():
        match = re.fullmatch(r".+\[([^\]]+)\]: (\S+) (\S)(?: .*)?", line.strip())
        if not match:
            if line.strip():
                raise ValueError("invalid archive symbol provenance: " + line)
            continue
        member, symbol, kind = match.groups()
        if symbol in result:
            result[symbol].append(dict(member=member, kind=kind))
    return result


# The explicit legacy TLS adapter remains linkable; current public APIs must not require it.
LEGACY_CREDENTIAL_SYMBOLS = (
    "__set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW",
    "__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW",
)

RETIRED_SYMBOLS = (
    "_ZN10skroot_env29set_boot_fail_protect_enabledEPKcb",
    "_ZN10skroot_env28is_boot_fail_protect_enabledEPKc",
    "_ZN10skroot_env23set_adb_forced_disabledEPKcb",
    "_ZN10skroot_env22is_adb_forced_disabledEPKc",
    "_ZN10skroot_env22get_root_status_reportEPKc",
    "_ZN10skroot_env16restart_zygote64EPKc",
    "_ZN10skroot_env26test_skroot_basics_with_cbEPKcNS_9BasicItemEPFvS1_E",
    "_ZN10skroot_env34test_skroot_deafult_module_with_cbEPKcNS_17DeafultModuleNameEPFvS1_E",
)


def module_entry_symbols(header: str) -> list[str]:
    result = []
    for label in ("ENTRY", "IDENTITY", "INSTALL", "UNINSTALL", "WEBUI",
                  "LAST_SERVER_PORT", "BEFORE_SERVER_EXIT"):
        match = re.search(r"^#define MAPLESU_MODULE_" + label + r"_SYMBOL\s+(.+)$", header, re.M)
        if match is None:
            raise ValueError("Missing current module ABI symbol: " + label)
        strings = re.findall(r'"(?:\\.|[^"\\])*"', match.group(1))
        if not strings:
            raise ValueError("Invalid current module ABI symbol: " + label)
        result.append("".join(ast.literal_eval(item) for item in strings))
    return result


def structural_problems(gate: dict) -> list[str]:
    """Only measured T/U migration differs; every structural/tool failure stays fatal."""
    migrated = set()
    problems = []
    rows = gate.get("members") or []
    if gate.get("scope") != "full" or len(rows) != gate.get("expected_members") or not rows:
        problems.append("current ABI requires every archive member")
    for row in rows:
        if row.get("status") == "MISSING" or row.get("layout", {}).get("ref") != row.get("layout", {}).get("new"):
            problems.append("missing/layout-changing member: " + str(row.get("idx")))
        for problem in row.get("problems") or []:
            if re.fullmatch(r"[TU] (?:missing|extra) [0-9]+", problem):
                migrated.add(row["name"] + ": " + problem)
    problems.extend(problem for problem in gate.get("problems") or [] if problem not in migrated)
    if gate.get("deferred_idx") or gate.get("allowlist", {}).get("invalid") or gate.get("baseline", {}).get("invalid"):
        problems.append("deferred members or invalid comparison rules")
    return problems


def _function(signature: str):
    # Count top-level parameters, preserving template and callback commas.
    at = signature.find("(")
    if at < 0 or not signature.endswith(")"):
        return None
    name = signature[:at].split()[-1]
    parameters = signature[at + 1:-1]
    depth = 0
    count = int(bool(parameters) and parameters != "void")
    for char in parameters:
        if char in "(<[":
            depth += 1
        elif char in ")>]":
            depth -= 1
        elif char == "," and depth == 0:
            count += 1
    return name, count


def legacy_credential_problems(required_symbols) -> list[str]:
    return ["legacy credential required by keyless public API: " + symbol
            for symbol in sorted(set(required_symbols).intersection(LEGACY_CREDENTIAL_SYMBOLS))]


def retired_api_problems(raw_symbols: list[str], signatures: list[str],
                         required_signatures: list[str], *,
                         explicit_legacy: dict[str, str] | None = None) -> list[str]:
    # Callers may supply only the exact pairs whose actual source/member/ARM
    # contract was validated. The default remains the historical strict gate.
    if explicit_legacy:
        if len(raw_symbols) != len(signatures):
            return ["explicit legacy signature capture differs"]
        current = [(symbol, signature) for symbol, signature in zip(raw_symbols, signatures)
                   if explicit_legacy.get(symbol) != signature]
        raw_symbols = [symbol for symbol, _ in current]
        signatures = [signature for _, signature in current]
    problems = ["retired RootKey symbol: " + symbol for symbol in raw_symbols
                if symbol in RETIRED_SYMBOLS]
    expected = {}
    for signature in required_signatures:
        parsed = _function(signature)
        if parsed and parsed[0].startswith(("maplesu::sdk::", "maplesu::", "kernel_root::")):
            name, count = parsed
            expected.setdefault(name.rsplit("::", 1)[-1], set()).add(count)
    for signature in signatures:
        parsed = _function(signature)
        if not parsed or not parsed[0].startswith(("maplesu::sdk::", "skroot_env::", "kernel_root::")):
            continue
        name, count = parsed
        counts = expected.get(name.rsplit("::", 1)[-1])
        if counts and count not in counts:
            problems.append("retired parameter ABI: " + signature)
        if name.endswith("::parser_root_key_info"):
            problems.append("retired parser ABI: " + signature)
    return sorted(set(problems))
