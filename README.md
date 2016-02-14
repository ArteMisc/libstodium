# libstodium

*Though the API is reaching a stable point, there may still be breaking changes between commits.*

The goal of this library is to provide complete bindings of libsodium using JNI
for the Android platform. It also provides implementations that try to handle
the passing of data between the JVM and native code in a more efficient way, by
supporting Java's method(array, offset, length) style for native methods.

Credits to:
* [**Libsodium**](https://github.com/jedisct1/libsodium): author [Frank Denis](https://github.com/jedisct1) and [Contributors](https://github.com/jedisct1/libsodium/graphs/contributors)
* [**libsodium-jni**](https://github.com/joshjdevl/libsodium-jni): author [joshjdevl](https://github.com/joshjdevl) and [Contributors](https://github.com/joshjdevl/libsodium-jni/graphs/contributors)
* [**Robosodium**](https://github.com/GerardSoleCa/Robosodium): author [GerardSoleCa](https://github.com/GerardSoleCa) and [Contributors](https://github.com/GerardSoleCa/Robosodium/graphs/contributors)

### Target platform

The library is heavily focussed on intergration with Android Studio and working
on Android systems.

The supported Android API versions are:
* Min SDK Version: 16 (4.1 Jelly Bean)
* Target SDK Version: 23 (6.0 Marshmallow)

### How to install

*When you plan to use libstodium in an Android Studio project, I would recommend
cloning the repository into a subdirectory of the project root.*

1. To start, download this repository (there is no need to download libsodium, the setup script handles this):
  ```bash
  $ git clone https://github.com/ArteMisc/libstodium.git
  ```

2. (Optional) on Ubuntu, you can run this command to make sure everything is setup on your machine:
  ```bash
  $ ./install_system_dependencies.sh
  ```
  
3. Next, run the setup script:
  ```bash
  $ ./setup.sh # load Ndk and Swig, install libsodium and JNI bindings, cleanup
  ```

In order for setup to run correctly, the environment variable JAVA_HOME should be set.
If this is not the case, the script will quit. You can set the JAVA_HOME value using
`export JAVA_HOME=/path/to/java` or by running the command like this:
```bash
$ JAVA_HOME=/path/to/java ./setup.sh
```

### Notes:
* Do NOT run the script as root. You will be asked to allow sudo for a few specific commands during the script's execution.
* Currently supported architectures are:
  * mips
  * arm
  * arm-v7a
  * x86
  
### License

Each part has its own software license, including:
* **Libsodium** [ISC License](https://github.com/jedisct1/libsodium/blob/master/LICENSE)
* **libsodium-jni** [Apache License. Version 2.0](https://github.com/joshjdevl/libsodium-jni/blob/master/LICENSE.txt)
* **Robosodium** [Apache License. Version 2.0](https://github.com/GerardSoleCa/Robosodium/blob/master/LICENSE.txt)
* **libstodium** [Apache License. Version 2.0](https://github.com/ArteMisc/libstodium/blob/master/LICENSE.txt)

### TODO
* Improve the API, provide more docs.
* Make the API compatible with Java's native Security interfaces.
* Add tests.
* Support more architectures as they come along (mainly 64-bits archs).
* Add code examples to the Readme.
* Add a guide for adding the project as Android Studio module to a project.
* Add support for Maven.
