rem server address
set kms_server=minskio.co.uk
rem windows activation
slmgr/skms %kms_server% && slmgr/ato
rem office activation, if it's installed
if exist "%ProgramFiles(x86)%\Microsoft Office\Office14\OSPP.VBS" cscript "%ProgramFiles(x86)%\Microsoft Office\Office14\OSPP.VBS" /sethst:%kms_server% && cscript "%ProgramFiles(x86)%\Microsoft Office\Office14\OSPP.VBS" /act