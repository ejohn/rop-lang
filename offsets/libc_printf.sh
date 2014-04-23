#!/bin/bash

/usr/bin/env gdb -batch -x libc_printf.gdb ../libc.so.6 > libc_printf.out
