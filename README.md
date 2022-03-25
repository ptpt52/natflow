# natflow

A fast forwarding stanalone kernel module with zero-patch to kernel. It could be a lite replacement of kmod-ipt-offload.

## Notes
Only work for x-wrt(https://github.com/x-wrt/x-wrt)

hwnat support for mt7621/mt7622
```
port--port hwnat supported:
port---ppe---port

wifi--port hwnat supported:
wifi--cpu--ppe---port
```

the wifi pure hardware nat for mt7622 is not supported yet. for now it just works as mt7621
```
wifi--cpu--ppe--port
```

## build
To build with path and urllogger module run:
```
make EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER"
```

`CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH` option to make hwnat ext dev work via vlan hash mode, this mode would disable bridge vlan filter. this is required on MT7622 if hwnat ext dev is needed.
```
make EXTRA_CFLAGS="-DCONFIG_HWNAT_EXTDEV_USE_VLAN_HASH"
```

`CONFIG_HWNAT_EXTDEV_DISABLED` option to disable hwnat ext dev. if this is set, bridge vlan filter could be sure to work on MT7622.
```
make EXTRA_CFLAGS="-DCONFIG_HWNAT_EXTDEV_DISABLED"
```
