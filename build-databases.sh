#!/bin/sh
[[ $(git rev-parse --show-toplevel) == $(pwd) ]] || {
    echo "This script must be run from the root of the workshop repository."
    exit 1
}

for i in {1..3}; do
    SRCDIR=$(pwd)/tests-common
    DB=$(pwd)/cpp-dataflow-part$i-database

    echo $DB
    test -d "$DB" && rm -fR "$DB"
    mkdir -p "$DB"

    codeql database create --language=cpp -s "$SRCDIR" -j 8 -v $DB --command="clang -fsyntax-only $SRCDIR/test_part$i.c"
done