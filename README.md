# AutoConnect
Find connection details of a MultiSense device that is connected to your computers network interface. (Works for both Ubuntu and Windows)


Can be run as standalone executable and print results to console or embedded into another program using shared memory between processes to share a JSON object with results.

## Usage
Clone the git repo and build the MultiSense Viewer

### Ubuntu and Windows instructions:
Open a <b> linux terminal </b> or a windows <b> developer command prompt and type </b>
```sh
$ git clone https://github.com/M-Gjerde/AutoConnect
$ cd AutoConnect
$ mkdir build && cd build
$ cmake ..
$ cmake --build . --config Release
```
Executables will be located in ${Build}/bin folder.


Must be run as root. So in a Linux Terminal
```sh
$ sudo ./AutoConnect -c on -i off # -c on for logging to console. -i off for not opening shared memory descriptor
```
Windows users should open command prompt as admin and run:
```sh
$ .\AutoConnect.exe -c on -i off # -c on for logging to console. -i off for not opening shared memory descriptor
```

The autoconnect tool will run for 60 seconds before shutting down.

### For use in another program
Check ReadSharedMemory.h in MultiSense-Viewer source code. Contains sample for both Windows and Ubuntu.

Link here:
https://github.com/M-Gjerde/MultiSense-Viewer/blob/master/include/Viewer/Tools/ReadSharedMemory.h
