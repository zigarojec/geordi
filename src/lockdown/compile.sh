#!/bin/sh
gcc lockdown.c -o lockdownsl -lseccomp -static
