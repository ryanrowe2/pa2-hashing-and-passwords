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
    -o "APT::Update::Error-Mode=any"
    -o "Acquire::Retries=0"
    -o "Acquire::Languages=none"
    -o "Acquire::IndexTargets::deb::CNF::DefaultEnabled=false"
  )
}

pa2_apt_cleanup() {
  if [[ -n ${PA2_APT_DIR:-} ]]; then
    rm -rf -- "$PA2_APT_DIR"
  fi
}
