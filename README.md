## OpenRISC 1000 support for IDA 7.x

Place the `or1k.py` in the `procs` directory.
If you don't see "OpenRISC 1000 (or1k)" in the CPU selection, then check if Python support is working in IDA.

You can switch between delay-slot and no-delay mode by changing the value of the `ND` in the dialog box displayed by pressing Alt-G.

* A non-zero value of `ND` means no delay.

* On the CPU this mode is controlled by the `ND` bit of the special-purpose register `CPUCFGR`.

