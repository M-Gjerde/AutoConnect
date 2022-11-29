# AutoConnect
AutoConnect library for MultiSense cameras for use with LibMultiSense


## For use in another program
1. Create Instance of AutoConnect
2. Call instance.run() to start scanning for adapters and searching

call instance.adapters() to get a list of supported adapters that autoconnect found
<br> call instance.cameras() to get a list of cameras
<br> call instance.log() to get the latest status update of search