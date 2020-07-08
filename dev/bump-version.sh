#!/bin/bash

# This script will increment the semver minor & patch version
# The major version still should be manually maintained

# Set variable to the entire 7th line in version.go
VERSION_VAR=$(sed '7q;d' pkg/pkiaas/version.go)

# Remove all preceding text to first "
VERSION="${VERSION_VAR#*\"}"
# Remove ending "
VERSION="${VERSION%%\"*}"
# Retrieve minor version
MINOR_SETUP="${VERSION#*.}"
MINOR_VER="${MINOR_SETUP%%.*}"
# Retrieve patch version
PATCH_VER="${MINOR_SETUP#*.}"

# Increment minor version if patch reaches 10
if [[ $PATCH_VER == 10 ]]; then
    (( MINOR_VER++ ))
    (( PATCH_VER++ ))
# Otherwise, just increment patch version
else
    (( PATCH_VER++ ))
fi

# Find current version in version.go and replace with new version
sed -i "s/var Version = \"${VERSION}\"/var Version = \"0.7.1\"/" pkg/pkiaas/version.go