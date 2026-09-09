# Synthetic UEFI fixtures

`task1-shape.hex` is hand-built solely from the public UEFI shape approved by Task 1:
one HardDrive node, one FilePath node, one EndEntire node, and opaque binary optional data.
Its partition values, signature bytes, description, path, and optional data are synthetic. It
does not contain or derive from BootHop's private firmware capture.
