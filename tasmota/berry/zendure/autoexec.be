# autoexec.be - loads the Zendure battery executor on every boot.
#
# Deployment (spec Part 2): upload BOTH `zendure.be` and this file to the device's flat
# filesystem root (Console > Manage File System, or `ffs`/webserver upload) - not into a
# subfolder. Tasmota runs autoexec.be automatically after every (re)boot.
#
# Using compile('zendure.be','file')() rather than `import zendure`: on this device,
# `import`'s "", ".bec", ".be" suffix-retry loop failed to reach the ".be" attempt at all
# (raised "cannot open file 'zendure'."/"...'zendure.bec'." even though zendure.be was
# present and valid) - compiling the exact filename directly and calling the closure
# sidesteps that lookup entirely and is what's been confirmed working on this unit.
compile('zendure.be', 'file')()
