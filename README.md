autofsync
=========

Intercepts `write()` call, and calls `fdatasync()` when certain amount of data
were written to a file. Limit size is adjusted at run time to keep `fdatasync()`
durations around predefined value. The goal is to express writeback cache size
limit in seconds rather than in bytes.

Library is supposed to be injected into applications with the help of
`LD_PRELOAD`.
