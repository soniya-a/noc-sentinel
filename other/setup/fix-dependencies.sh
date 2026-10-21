#!/usr/bin/env bash

set -euo pipefail

# This script keeps the classic bin/Makefile layout working on a plain git checkout.
SYSTEMC_VERSION="systemc-2.3.1"
SYSTEMC_ARCHIVE_VERSION="${SYSTEMC_VERSION}a"
SYSTEMC_ARCHIVE="${SYSTEMC_ARCHIVE_VERSION}.tar.gz"
SYSTEMC_URL="https://www.accellera.org/images/downloads/standards/systemc/${SYSTEMC_ARCHIVE}"

YAML_GIT_URL="${YAML_GIT_URL:-https://github.com/jbeder/yaml-cpp.git}"
YAML_GIT_REF="${YAML_GIT_REF:-yaml-cpp-0.6.0}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"
LIBS_DIR="${BIN_DIR}/libs"
BACKUP_DIR="${REPO_ROOT}/other/deps-backup"

SYSTEMC_DIR="${LIBS_DIR}/${SYSTEMC_VERSION}"
YAML_DIR="${LIBS_DIR}/yaml-cpp"
YAML_BUILD_DIR="${YAML_DIR}/lib"
BACKUP_SYSTEMC_ARCHIVE="${BACKUP_DIR}/${SYSTEMC_ARCHIVE}"
BACKUP_YAML_ARCHIVE="${BACKUP_DIR}/yaml-cpp-yaml-cpp-0.6.0-2dc9ce159652.tar.gz"

usage() {
    cat <<EOF
Usage: $(basename "$0")

Download and build the local dependencies expected by bin/Makefile:
  - SystemC in ${SYSTEMC_DIR}
  - yaml-cpp in ${YAML_DIR}

Optional environment overrides:
  CC, CXX, JOBS, CONFIGURE_FLAGS, YAML_GIT_URL, YAML_GIT_REF
EOF
}

log() {
    printf '[deps] %s\n' "$*"
}

fail() {
    printf '[deps] Error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

resolve_cc() {
    printf '%s\n' "${CC:-gcc}"
}

resolve_cxx() {
    printf '%s\n' "${CXX:-g++}"
}

detect_jobs() {
    # Prefer the host CPU count when available to speed up local builds.
    if command -v getconf >/dev/null 2>&1; then
        getconf _NPROCESSORS_ONLN 2>/dev/null && return
    fi

    if command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.ncpu 2>/dev/null && return
    fi

    printf '1\n'
}

download_file() {
    local url="$1"
    local output_path="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -L --fail --output "${output_path}" "${url}"
        return
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -O "${output_path}" "${url}"
        return
    fi

    fail "Missing required command: curl or wget"
}

systemc_ready() {
    local lib_dir

    [[ -f "${SYSTEMC_DIR}/include/systemc.h" ]] || return 1

    for lib_dir in "${SYSTEMC_DIR}"/lib-*; do
        [[ -d "${lib_dir}" ]] || continue
        [[ -f "${lib_dir}/libsystemc.a" || -f "${lib_dir}/libsystemc.so" || -f "${lib_dir}/libsystemc.dylib" ]] && return 0
    done

    return 1
}

download_systemc_archive() {
    local archive_path="${LIBS_DIR}/${SYSTEMC_ARCHIVE}"

    if [[ -f "${archive_path}" ]]; then
        log "Using existing archive ${archive_path}"
        return
    fi

    if [[ -f "${BACKUP_SYSTEMC_ARCHIVE}" ]]; then
        log "Using local backup ${BACKUP_SYSTEMC_ARCHIVE}"
        cp "${BACKUP_SYSTEMC_ARCHIVE}" "${archive_path}"
        return
    fi

    log "Downloading ${SYSTEMC_ARCHIVE}"
    download_file "${SYSTEMC_URL}" "${archive_path}"
}

extract_systemc_source() {
    local archive_path="${LIBS_DIR}/${SYSTEMC_ARCHIVE}"
    local extracted_dir="${LIBS_DIR}/${SYSTEMC_ARCHIVE_VERSION}"

    if [[ -d "${SYSTEMC_DIR}" ]]; then
        return
    fi

    [[ -f "${archive_path}" ]] || fail "Archive ${archive_path} does not exist"

    log "Extracting ${SYSTEMC_ARCHIVE}"
    tar -xzf "${archive_path}" -C "${LIBS_DIR}"

    if [[ -d "${extracted_dir}" && "${extracted_dir}" != "${SYSTEMC_DIR}" ]]; then
        mv "${extracted_dir}" "${SYSTEMC_DIR}"
    fi

    [[ -d "${SYSTEMC_DIR}" ]] || fail "Expected ${SYSTEMC_DIR} after extraction"
}

patch_macos_arm_systemc() {
    local configure_script="${SYSTEMC_DIR}/configure"
    local temp_file="${configure_script}.tmp"

    [[ "$(uname -s)" == "Darwin" ]] || return 0
    [[ "$(uname -m)" == "arm64" ]] || return 0
    [[ -f "${configure_script}" ]] || fail "Missing configure script in ${SYSTEMC_DIR}"

    if grep -q 'TARGET_ARCH="macosarm"' "${configure_script}"; then
        return 0
    fi

    # SystemC 2.3.1 does not recognize Apple Silicon out of the box.
    log "Patching SystemC configure for Apple Silicon"

    if ! awk '
        BEGIN {
            patched = 0
            in_apple_case = 0
            in_target_cpu_case = 0
        }
        /\*-apple-\*/ { in_apple_case = 1 }
        in_apple_case && /case "\$target_cpu" in/ { in_target_cpu_case = 1 }
        in_target_cpu_case && /^[[:space:]]*\*\)/ && patched == 0 {
            print "            arm64 | aarch64 | arm)"
            print "                TARGET_ARCH=\"macosarm\""
            print "                CPU_ARCH=\"arm64\""
            print "                QT_ARCH=\"pthreads\""
            print "                ;;"
            patched = 1
        }
        { print }
        in_target_cpu_case && /^[[:space:]]*esac$/ {
            in_target_cpu_case = 0
            in_apple_case = 0
        }
        END { if (patched == 0) exit 1 }
    ' "${configure_script}" > "${temp_file}"; then
        rm -f "${temp_file}"
        fail "Failed to patch ${configure_script} for Apple Silicon"
    fi

    mv "${temp_file}" "${configure_script}"
    chmod +x "${configure_script}"
}

build_systemc() {
    local build_dir="${SYSTEMC_DIR}/objdir"
    local jobs
    local configure_args=()

    jobs="${JOBS:-$(detect_jobs)}"

    if [[ -n "${CONFIGURE_FLAGS:-}" ]]; then
        # shellcheck disable=SC2206
        configure_args=(${CONFIGURE_FLAGS})
    fi

    mkdir -p "${build_dir}"

    log "Building SystemC in ${build_dir}"

    (
        cd "${build_dir}"
        export CXX="${CXX:-$(resolve_cxx)}"
        export CC="${CC:-$(resolve_cc)}"
        if [[ ${#configure_args[@]} -gt 0 ]]; then
            ../configure "${configure_args[@]}"
        else
            ../configure
        fi
        make -j"${jobs}"
        make install
    )
}

ensure_systemc() {
    if systemc_ready; then
        log "SystemC already available in ${SYSTEMC_DIR}"
        return
    fi

    require_command tar
    require_command make
    require_command "$(resolve_cc)"
    require_command "$(resolve_cxx)"

    download_systemc_archive
    extract_systemc_source
    patch_macos_arm_systemc
    build_systemc

    systemc_ready || fail "SystemC build finished but the expected headers or libraries were not found"
    log "SystemC is ready in ${SYSTEMC_DIR}"
}

yaml_ready() {
    [[ -f "${YAML_DIR}/include/yaml-cpp/yaml.h" ]] || return 1
    [[ -f "${YAML_BUILD_DIR}/libyaml-cpp.a" || -f "${YAML_BUILD_DIR}/libyaml-cpp.so" || -f "${YAML_BUILD_DIR}/libyaml-cpp.dylib" ]] || return 1
    return 0
}

patch_yaml_for_modern_cmake() {
    local cmake_lists="${YAML_DIR}/CMakeLists.txt"
    local temp_file="${cmake_lists}.tmp"

    [[ -f "${cmake_lists}" ]] || fail "Missing ${cmake_lists}"

    if ! grep -q 'cmake_minimum_required(VERSION 2.6)' "${cmake_lists}" \
        && ! grep -q 'cmake_policy(SET CMP0012 OLD)' "${cmake_lists}" \
        && ! grep -q 'cmake_policy(SET CMP0015 OLD)' "${cmake_lists}"; then
        return
    fi

    # yaml-cpp 0.6.0 predates modern CMake policy defaults.
    log "Patching yaml-cpp CMakeLists.txt for modern CMake"

    awk '
        {
            gsub(/cmake_minimum_required\(VERSION 2\.6\)/, "cmake_minimum_required(VERSION 3.5)")
            gsub(/cmake_policy\(SET CMP0012 OLD\)/, "cmake_policy(SET CMP0012 NEW)")
            gsub(/cmake_policy\(SET CMP0015 OLD\)/, "cmake_policy(SET CMP0015 NEW)")
            print
        }
    ' "${cmake_lists}" > "${temp_file}"

    mv "${temp_file}" "${cmake_lists}"
}

ensure_yaml_source() {
    if [[ -d "${YAML_DIR}" ]]; then
        [[ -f "${YAML_DIR}/CMakeLists.txt" ]] || fail "Expected ${YAML_DIR} to contain yaml-cpp sources"
        log "Using existing yaml-cpp source in ${YAML_DIR}"
        return
    fi

    if [[ -f "${BACKUP_YAML_ARCHIVE}" ]]; then
        require_command tar
        log "Using local backup ${BACKUP_YAML_ARCHIVE}"
        tar -xzf "${BACKUP_YAML_ARCHIVE}" -C "${LIBS_DIR}"
        [[ -f "${YAML_DIR}/CMakeLists.txt" ]] || fail "Expected ${YAML_DIR} after extracting ${BACKUP_YAML_ARCHIVE}"
        return
    fi

    require_command git

    log "Cloning yaml-cpp ${YAML_GIT_REF}"
    git clone --branch "${YAML_GIT_REF}" --depth 1 "${YAML_GIT_URL}" "${YAML_DIR}"
}

build_yaml() {
    require_command cmake

    mkdir -p "${YAML_BUILD_DIR}"
    patch_yaml_for_modern_cmake

    log "Building yaml-cpp in ${YAML_BUILD_DIR}"

    (
        cd "${YAML_BUILD_DIR}"
        # Keep the local static build minimal and avoid package-registry writes.
        cmake \
            -DCMAKE_C_COMPILER="$(resolve_cc)" \
            -DCMAKE_CXX_COMPILER="$(resolve_cxx)" \
            -DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON \
            -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
            -DYAML_CPP_BUILD_TESTS=OFF \
            -DYAML_CPP_BUILD_TOOLS=OFF \
            -DYAML_CPP_BUILD_CONTRIB=OFF \
            ..
        cmake --build .
    )
}

ensure_yaml() {
    if yaml_ready; then
        log "yaml-cpp already available in ${YAML_DIR}"
        return
    fi

    require_command "$(resolve_cc)"
    require_command "$(resolve_cxx)"

    ensure_yaml_source
    build_yaml

    yaml_ready || fail "yaml-cpp build finished but the expected headers or libraries were not found"
    log "yaml-cpp is ready in ${YAML_DIR}"
}

main() {
    if [[ $# -gt 0 ]]; then
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "Unknown argument: $1"
                ;;
        esac
    fi

    [[ -f "${BIN_DIR}/Makefile" ]] || fail "Could not find ${BIN_DIR}/Makefile"

    mkdir -p "${LIBS_DIR}"

    # Install only what bin/Makefile expects for a local source checkout.
    ensure_systemc
    ensure_yaml

    log "Dependencies are ready under ${LIBS_DIR}"
}

main "$@"
