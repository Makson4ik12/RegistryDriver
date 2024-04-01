# RegistryDriver
Windows driver for controlling access to registry objects and a console application for setting the mandatory access level for registry objects and applications

## Desctiption
The driver intercepts all registry operations (reading, changing, creating keys) and compares the access levels of the thread that wants to interact with the registry object and the object itself. If the thread has a lower access level than the object, it is denied access

The console application is designed to set access levels for registry objects and applications. All rules are written to an xml file, which is placed in one of the registry keys, which only this application has access to. When creating/changing each rule, it is sent to the driver using IoctlRequest

## Requirements

- pugixml, whose files are already included in the console application project
