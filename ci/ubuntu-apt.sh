#!/usr/bin/env bash
# Restrict PA2 dependency operations to Canonical's signed Ubuntu repositories.
# Never permit unconfigured third-party repositories to supply locked packages.
pa2_apt_init() {
  if [[ ! -r /usr/share/keyrings/ubuntu-archive-keyring.gpg ]]; then
    printf '::error::Ubuntu archive signing keyring is unavailable\n' >&2
    return 2
  fi
  PA2_APT_DIR=$(mktemp -d)
  chmod 755 "$PA2_APT_DIR"
}

pa2_apt_select() {
  local mode=$1 snapshot=$2
  local repo security
  case "$mode" in
    snapshot)
      [[ "$snapshot" =~ ^20[0-9]{6}T[0-9]{6}Z$ ]] || return 2
      repo="https://snapshot.ubuntu.com/ubuntu/$snapshot"
      security="$repo"
      ;;
    current)
      repo="http://archive.ubuntu.com/ubuntu"
      security="http://security.ubuntu.com/ubuntu"
      ;;
    *) printf '::error::Unsupported APT source mode\n' >&2; return 2 ;;
  esac
  PA2_APT_MODE=$mode
  PA2_APT_SNAPSHOT=$snapshot
  # Isolate both apt-cache and apt-get from pre-existing hosted-runner indexes.
  # Separate modes ensure snapshot indexes cannot contaminate current archives.
  PA2_APT_LISTS="$PA2_APT_DIR/lists-$mode"
  mkdir -p "$PA2_APT_LISTS/partial"
  chmod 755 "$PA2_APT_LISTS" "$PA2_APT_LISTS/partial"
  PA2_APT_LIST="$PA2_APT_DIR/pa2-$mode.list"
  {
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s noble main universe\n' "$repo"
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s noble-updates main universe\n' "$repo"
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s noble-security main universe\n' "$security"
  } > "$PA2_APT_LIST"
  chmod 644 "$PA2_APT_LIST"
  PA2_APT_OPTIONS=(
    -o "Dir::Etc::sourcelist=$PA2_APT_LIST"
    -o "Dir::Etc::sourceparts=-"
    -o "Dir::State::lists=$PA2_APT_LISTS"
    -o "APT::Get::AllowUnauthenticated=false"
    -o "APT::Update::Error-Mode=any"
    -o "Acquire::Retries=0"
    -o "Acquire::Languages=none"
    -o "Acquire::IndexTargets::deb::CNF::DefaultEnabled=false"
  )
}

# Verify that the requested package and exact pin are represented in the
# authenticated archive indexes, not only /var/lib/dpkg/status.
pa2_apt_check_available() {
  local purpose=$1 spec=$2 name pinned listing status
  name=${spec%%=*}
  pinned=${spec#*=}
  if ! listing=$(apt-cache "${PA2_APT_OPTIONS[@]}" madison "$name"); then
    printf '::error::Unable to query authenticated versions for %s\n' "$name" >&2
    return 2
  fi
  if printf '%s\n' "$listing" |
     python3 ci/verify-ubuntu-candidates.py "$purpose" "$PA2_APT_MODE" "${PA2_APT_SNAPSHOT:--}" "$name" "$pinned"; then
    return 0
  else
    status=$?
    return "$status"
  fi
}

pa2_apt_cleanup() {
  if [[ -n ${PA2_APT_DIR:-} ]]; then
    # APT may have created root-owned index directories inside this temp tree.
    if ! rm -rf -- "$PA2_APT_DIR" 2>/dev/null; then
      sudo rm -rf -- "$PA2_APT_DIR"
    fi
  fi
}
