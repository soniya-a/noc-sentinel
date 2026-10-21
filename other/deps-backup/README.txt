Noxim dependency backups
========================

This directory stores local backup copies of the third-party source archives used by
`./build.sh` and `./other/setup/fix-dependencies.sh`.

Files kept here
---------------
- `systemc-2.3.1a.tar.gz`
- `yaml-cpp-yaml-cpp-0.6.0-2dc9ce159652.tar.gz`
- `SHA256SUMS.txt`

Normal usage
------------
Just run:

    ./build.sh

The dependency fixer now checks this directory before trying to download anything from the internet.
If the upstream URLs disappear in the future, keeping these files here is enough for the build to
continue working.

What to do if online downloads stop working
-------------------------------------------
1. Make sure the backup files listed above are present in `other/deps-backup/`.
2. From the repository root, run:

       ./build.sh

3. The script will:
   - copy `systemc-2.3.1a.tar.gz` into `bin/libs/` and build SystemC from it
   - extract the yaml-cpp backup into `bin/libs/yaml-cpp/` and build it locally
   - compile `bin/noxim`

If you moved these archives somewhere else for safekeeping, copy them back into
`other/deps-backup/` and rerun `./build.sh`.

Optional checksum verification
------------------------------
To verify the backups before using them:

    shasum -a 256 -c other/deps-backup/SHA256SUMS.txt
