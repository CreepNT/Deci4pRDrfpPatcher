# Deci4pRDrfpPatcher

A module to patch the DevKit `SceDeci4pRDrfp` kernel module to enhance the features it provides.

This module is used in conjunction with the PlayStation®️ File System Driver (PSFSD) on the host computer to access files on a target, usually via the `V:` mountpoint.

# Features

* Replaces the seldom used `Vita Card` mountpoint with `os0` (can be customized)
* Forces kernel impersonation for all accesses to unlock the full filesystem (no more hidden files!)
