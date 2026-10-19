# Jetson telemetry fixtures (synthetic)

Hand-built (CLAUDE.md rule 27), not recordings from a device:

- `sysfs-orin-synthetic/`: a minimal sysfs / procfs tree as an Orin lays it
  out: the GPU load file AEGIS Core's idle guard reads
  (`sys/devices/platform/bus@0/17000000.gpu/load`, per mille), the GPU devfreq
  node (`cur_freq`, Hz), thermal zones by type, the kernel release, the
  device-tree model and `etc/nv_tegra_release`. Every value is made up.
- `tegrastats-synthetic.txt`: tegrastats lines in the formats it prints (with
  and without the leading timestamp; `GR3D_FREQ n%@[f,f]` on Orin,
  `GR3D_FREQ n%@f` and `GPU@` on older L4T). Every value is made up.

Replace them with recordings from a Jetson when the sm_87 port lands.
