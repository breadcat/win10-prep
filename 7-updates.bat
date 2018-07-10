rem install windows media framework, if they exist after mounting network
if exist Z:\images\windows/KB3133719-x64.msu wusa.exe Z:\images\windows/KB3133719-x64.msu /quiet /norestart
if exist Z:\images\windows/KB3133719-x86.msu wusa.exe Z:\images\windows/KB3133719-x86.msu /quiet /norestart