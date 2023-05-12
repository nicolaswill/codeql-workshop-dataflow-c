#!/bin/sh

# This script copies the test_part1.c, test_part2.c, and test_part3.c files 
# from the tests-common directory to the appropriate directories in the 
# solutions-tests and exercises-tests directories.
[[ $(git rev-parse --show-toplevel) == $(pwd) ]] || {
    echo "This script must be run from the root of the workshop repository."
    exit 1
}

SRCDIR=$(pwd)/tests-common

target_dirs=(
    $(pwd)/solutions-tests
    $(pwd)/exercises-tests
)

for dir in "${target_dirs[@]}"; do
    # copy test-part1.c to the Exercise1-Exercise6 directories
    for i in {1..5}; do
        cp $SRCDIR/test_part1.c $dir/Exercise$i/test.c
    done
    # copy test-part2.c to the Exercise7-Exercise11 directories
    for i in {7..12}; do
        cp $SRCDIR/test_part2.c $dir/Exercise$i/test.c
    done
    # copy test-part3.c to the Exercise13-Exercise15 directories
    for i in {13..16}; do
        cp $SRCDIR/test_part3.c $dir/Exercise$i/test.c
    done
done

exit 0
