#! /usr/bin/env bash
# Copyright (c) 2022 Sebastian Pipping <sebastian@pipping.org>
# Licensed under the GPL v2 or later

set -e

: ${CLANG_FORMAT:=clang-format}

args=(
    # Style option docs at https://clang.llvm.org/docs/ClangFormatStyleOptions.html
    --style='{
        Language: Cpp,
        BasedOnStyle: Google,

        AlignConsecutiveMacros: Consecutive,
        ColumnLimit: 120,
        DerivePointerAlignment: False,
        PointerAlignment: Middle,
        SortIncludes: Never,
    }'
    --verbose
    -i  # for in-place operation
)

if [[ $# -gt 0 ]]; then
    args+=( "$@" )
else
    ifs_backup="${IFS}"
    IFS=$'\n';
    args+=( $(git ls-files -z '*.[ch]' | tr '\0' '\n') )
    IFS="${ifs_backup}"
fi

set -x

exec "${CLANG_FORMAT}" "${args[@]}"
