# TiEtwAgent - ETW-based process injection detection
![msbuild](https://github.com/xinbailu/TiEtwAgent/actions/workflows/msbuild.yml/badge.svg)

This project was created to research, build and test different memory injection detection use cases and bypass techniques. The agent utilizes Microsoft-Windows-Threat-Intelligence event tracing provider, as a more modern and stable alternative to Userland-hooking, with the benefit of Kernel-mode visibility. 

The project depends on the [microsoft/krabsetw](https://github.com/microsoft/krabsetw) library for ETS setup and consumption.

An accompanying blog post can be found here: https://blog.redbluepurple.io/windows-security-research/kernel-tracing-injection-detection

![gif](https://i.imgur.com/M9QXk1z.gif)

# Adding new detections 
Detection functions can be easily added in `DetectionLogic.cpp`, and called from `detect_event(GenericEvent evt)` for any source event type. Support for new event fields can be easily added by appending their name to the map in `GenericEvent` class declaration.

# Setup instructions
Assuming you do not have a Microsoft-trusted signing certificate:
- Put your machine in the test signing mode with bcdedit
- Generate a self-signed certificate with ELAM and Code Signing EKU 
- Sign TiEtwAgent.exe and your ELAM driver with the certificate 
- ./TiEtwAgent install
- net start TiEtwAgent
- Look for logs, by default in C:\Windows\Temp\TiEtwAgent.txt

# TODO
- [x] PPL Service, event parsing 
- [x] First detection  
- [ ] Detection lifecycle 
- [ ] Risk based lifecycle 

PS. If you do not want to write an ELAM driver, you can get one from https://github.com/pathtofile/PPLRunner/tree/main/elam_driver

Special thanks to [@pathtofile](https://github.com/pathtofile) for the post here: https://blog.tofile.dev/2020/12/16/elam.html
