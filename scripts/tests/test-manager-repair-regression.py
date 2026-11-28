"""Compile complete current Manager sources and run the retained JVM regression cohort."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path):
    return {"path": path.as_posix(), "bytes": path.stat().st_size, "sha256": sha(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basis-plan", type=Path, required=True)
    parser.add_argument("--source-basis", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--extra-test", type=Path, action="append", default=[])
    parser.add_argument("--all-production", action="store_true")
    parser.add_argument("--compile-only", action="store_true")
    args = parser.parse_args()
    basis = json.loads(args.basis_plan.read_text(encoding="utf-8-sig"))
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    classes = out / "classes"
    classes.mkdir()
    production = {Path(row["path"]) for row in basis["originalSources"] if "/src/main/" in row["path"]}
    current_production = sorted((ROOT / "manager/src/main").rglob("*.kt"))
    current_source_rows = [identity(path) for path in current_production]
    if args.all_production:
        production.update(current_production)
    if args.source_basis:
        for path in current_production:
            prior = args.source_basis / path.relative_to(ROOT)
            if not prior.is_file() or sha(prior) != sha(path):
                production.add(path)
    tests = {Path(row["path"]) for row in basis["originalSources"] if "/src/test/" in row["path"]}
    tests.update(path.resolve() for path in args.extra_test)
    if args.compile_only:
        tests.clear()
    sources = sorted(production | tests)
    snapshots = []
    test_classes = []
    for path in sources:
        copy = out / "inputs" / path.relative_to(ROOT)
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, copy)
        snapshots.append({"source": identity(path), "snapshot": identity(copy), "production": path in production})
        if path in tests:
            text = copy.read_text(encoding="utf-8-sig")
            package = re.search(r"^package\s+([\w.]+)", text, re.MULTILINE)
            test_classes.extend(package[1] + "." + match[1]
                                for match in re.finditer(r"^class\s+(\w+Test)\b", text, re.MULTILINE))
    assert len(test_classes) == len(set(test_classes)), "Duplicate test class"
    if not args.compile_only:
        assert set(basis["testClasses"]).issubset(test_classes), "Retained test cohort was narrowed"
    compile_cp = [classes.as_posix(), *basis["compileClasspath"][1:]]
    runtime_cp = [classes.as_posix(), *basis["runtimeClasspath"][1:]]
    launch = basis["commands"][0]["argv"]
    compiler_cp = launch[launch.index("-cp") + 1]
    java = launch[0]
    compiler_args = ["-no-stdlib", "-no-reflect", "-jvm-target", "21", "-module-name", "manager",
                     "-Xfriend-paths=" + os.pathsep.join(basis["friends"]),
                     "-classpath", os.pathsep.join(compile_cp), "-d", classes.as_posix(),
                     "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
                     "-opt-in=androidx.compose.material3.ExperimentalMaterial3ExpressiveApi"]
    compiler_args.extend("-Xplugin=" + Path(path).as_posix() for path in basis["compilerPlugins"])
    compiler_args.extend(row["snapshot"]["path"] for row in snapshots)
    argfile = out / "kotlinc.args"
    argfile.write_text("\n".join('"' + value.replace("\\", "/") + '"' for value in compiler_args) + "\n", encoding="utf-8")
    commands = [("K2", [java, "-Xmx1536m", "-Dfile.encoding=UTF-8", "-cp", compiler_cp,
                        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "@" + argfile.as_posix()])]
    if not args.compile_only:
        commands.append(("JUnit", [java, "-Xmx768m", "-Dfile.encoding=UTF-8", "-Dmaplesu.repo=" + ROOT.as_posix(),
                                   "-cp", os.pathsep.join(runtime_cp), "org.junit.runner.JUnitCore", *test_classes]))
    external_files = {Path(path) for path in compile_cp[1:] + runtime_cp[1:] + compiler_cp.split(os.pathsep)
                      + basis["compilerPlugins"] if Path(path).is_file()}
    basis_manifest = Path(basis["productionManifest"]["path"])
    original_basis = json.loads(basis_manifest.read_text(encoding="utf-8-sig"))["rows"]
    dependency_rows = [identity(path) for path in sorted(external_files)] + original_basis
    dependency_rows.extend(identity(path) for entry in runtime_cp[1:] if "platform-fixtures" in entry
                           for path in sorted(Path(entry).rglob("*")) if path.is_file())
    plan = {"schema": "maplesu-current-manager-regression/1", "basisPlan": identity(args.basis_plan.resolve()),
            "sourceBasis": str(args.source_basis), "sourceSnapshots": snapshots, "dependencies": dependency_rows,
            "allCurrentProductionSources": current_source_rows,
            "productionSourceCount": len(production), "testSourceCount": len(tests), "testClasses": test_classes,
            "commands": [{"phase": phase, "argv": command} for phase, command in commands],
            "scope": "Complete selected current Kotlin files over retained real Gradle dependency classes and R.jar; Android boundary fixtures only at JUnit runtime; no native/SDK/APK/device qualification."}
    (out / "PLAN.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = {"schema": "maplesu-current-manager-regression-result/1", "executions": [], "tests": None,
              "failures": None, "compilationFailure": None, "preparationFailure": None, "sourceDrift": []}
    drift = [row["path"] for row in dependency_rows if not Path(row["path"]).is_file() or sha(Path(row["path"])) != row["sha256"]]
    if drift:
        result["preparationFailure"] = {"kind": "DEPENDENCY_IDENTITY_DRIFT", "paths": drift}
    else:
        env = os.environ.copy()
        temp = out / "temp"
        temp.mkdir()
        env.update(TEMP=str(temp), TMP=str(temp))
        for phase, command in commands:
            print(phase + " started", flush=True)
            started = time.monotonic()
            try:
                process = subprocess.run(command, cwd=ROOT / "manager", stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900, env=env)
            except subprocess.TimeoutExpired as error:
                (out / (phase.lower() + ".log")).write_bytes(error.stdout or b"")
                result["preparationFailure"] = {"kind": "TIMEOUT", "phase": phase}
                break
            log = out / (phase.lower() + ".log")
            log.write_bytes(process.stdout)
            result["executions"].append({"phase": phase, "exitCode": process.returncode,
                                         "seconds": round(time.monotonic() - started, 3), "log": identity(log)})
            decoded = process.stdout.decode("utf-8", errors="replace")
            print(phase + " exit=" + str(process.returncode), flush=True)
            if phase == "K2" and process.returncode:
                result["compilationFailure"] = process.returncode
                result["compilerErrors"] = [line for line in decoded.splitlines() if "error:" in line]
                break
            if phase == "JUnit":
                passed = re.search(r"OK \((\d+) tests?\)", decoded)
                failed = re.search(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+)", decoded)
                if passed:
                    result.update(tests=int(passed[1]), failures=0)
                elif failed:
                    result.update(tests=int(failed[1]), failures=int(failed[2]))
                    result["failureMethods"] = re.findall(r"^\d+\) (.+)$", decoded, re.MULTILINE)
                else:
                    result["preparationFailure"] = "JUNIT_SUMMARY_MISSING"
    result["sourceDrift"] = [row["source"]["path"] for row in snapshots
                             if sha(Path(row["source"]["path"])) != row["source"]["sha256"]]
    result["sourceDrift"] = sorted(set(result["sourceDrift"] + [row["path"] for row in current_source_rows
                                   if sha(Path(row["path"])) != row["sha256"]]))
    dependency_drift = [row["path"] for row in dependency_rows
                        if not Path(row["path"]).is_file() or sha(Path(row["path"])) != row["sha256"]]
    if dependency_drift:
        result["preparationFailure"] = {"kind": "DEPENDENCY_IDENTITY_DRIFT_AFTER_EXECUTION", "paths": dependency_drift}
    result["generatedFileCount"] = sum(path.is_file() for path in classes.rglob("*"))
    result["passed"] = result["compilationFailure"] is None and result["preparationFailure"] is None and (
        args.compile_only or result["failures"] == 0)
    result["currentSourcesQualified"] = result["passed"] and not result["sourceDrift"]
    result["scope"] = plan["scope"]
    (out / "RESULT.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 0 if result["currentSourcesQualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
