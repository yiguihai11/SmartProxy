#!/usr/bin/env python3
"""Inject a release signingConfig into the scaffolded app/build.gradle.kts.

The Android CLI scaffolds a fresh project on every CI run, so this patch is
applied each time. Credentials come from env vars; defaults are the standard
Android *debug* signing convention (debug.keystore / android / androiddebugkey),
so the workflow stays self-contained with zero GitHub secrets.

Usage:  python3 scripts/android_sign_patch.py <path/to/app/build.gradle.kts>
"""
import os
import re
import sys

path = sys.argv[1]
src = open(path).read()

signing_block = """    signingConfigs {
        create("release") {
            storeFile = file(System.getenv("KEYSTORE_FILE") ?: "debug.keystore")
            storePassword = System.getenv("KEYSTORE_PASSWORD") ?: "android"
            keyAlias = System.getenv("KEY_ALIAS") ?: "androiddebugkey"
            keyPassword = System.getenv("KEY_PASSWORD") ?: "android"
        }
    }
"""

# 1. signingConfigs block right after the `android {` line.
if 'signingConfigs' not in src:
    src = re.sub(r'(?m)^(android\s*\{\s*)$', r'\1\n' + signing_block, src, count=1)
    print('signingConfigs: injected')
else:
    print('signingConfigs: already present')

# 2. Wire it into the release buildType (right after `release {`).
marker = 'signingConfig = signingConfigs.getByName("release")'
if marker not in src:
    src = re.sub(r'(?m)^(\s*release\s*\{\s*)$', r'\1\n            ' + marker, src, count=1)
    print('release.signingConfig: injected')
else:
    print('release.signingConfig: already present')

open(path, 'w').write(src)
