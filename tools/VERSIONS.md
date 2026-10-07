# Tool versions

All tools live under `tools/` inside the project (nothing installed system-wide by this work).

| Tool | Version | Source | Notes |
|---|---|---|---|
| rizin | 0.9.1 (commit c3a90e92) @ windows-x86-64 | pre-installed by user | primary disassembler |
| rz-ghidra | v0.9.0 | github.com/rizinorg/rz-ghidra release `rz-ghidra-src-v0.9.0.tar.gz` (sha256 6e1027bb...fdf80f3) | built from source with MSVC 19.51 / VS Build Tools 2026 (18.10), CMake 4.3 + Ninja from VS; `scripts/build_rz_ghidra.bat`; zlib 1.3.1 fetched by CMake (pinned sha256) |
| Il2CppDumper | v6.7.46 net6 win | github.com/Perfare/Il2CppDumper release zip (sha256 d1117d66...ff765a), copied from mkt_archive/tools | latest release |
| Cpp2IL | 2022.1.0-pre-release.21 (+58fc404a) Windows exe | github.com/SamboyCoding/Cpp2IL release (sha256 663fb432...e04c) | latest release |
| .NET runtime | 6.0.36 and 10.0.11, SDK 10.0.400 | pre-installed | Il2CppDumper needs 6.0 |
| Python | CPython 3.14.7 venv in tools/venv (created with uv 0.12.15) | | |
| protobuf (py) | 7.36.2 | PyPI | |
| grpcio-tools | 1.84.0 | PyPI | provides `protoc` (python -m grpc_tools.protoc) |
| pyelftools | 0.33 | PyPI | |
| rzpipe | 0.6.2 | PyPI | |
| aiohttp | 3.14.4 | PyPI | server skeleton |
