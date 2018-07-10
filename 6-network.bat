rem connect to network shares
net use Z: \\atlas\media /USER:%username% /PERSISTENT:YES
net use Y: \\atlas\vault /USER:%username% /PERSISTENT:YES
net use X: \\atlas\downloads /USER:%username% /PERSISTENT:YES