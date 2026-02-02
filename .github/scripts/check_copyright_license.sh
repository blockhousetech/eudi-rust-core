#!/bin/bash
#
# Checks if all the Rust files in the project have the correct copyright
# & license header.

set -euo pipefail

readonly NOTICE=$(cat << EOF
// Copyright (C) 2020-2026  The Blockhouse Technology Limited (TBTL).
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
// License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
EOF
)

# Exclude `*.rs` files in any `target/` folder
RS_FILES=$(
  find . \
    -type d -name target -prune -o \
    -type f -name '*.rs' -print
)

files_missing_notice=()

for file in ${RS_FILES[@]}; do
  header=$(head -n "$(wc -l <<< "$NOTICE")" "${file}")
  if [[ "${header}" != "${NOTICE}" ]]; then
    files_missing_notice+=("${file}")
  fi
done

if [[ ${#files_missing_notice[@]} -gt 0 ]]; then
  echo "ERROR: The following files are missing or have an incorrect copyright notice:"
  for file in "${files_missing_notice[@]}"; do
    echo "  - ${file}"
  done
  exit 1
fi

echo "All *.rs files have the correct notice!"
