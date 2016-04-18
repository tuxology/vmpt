# VMPT
A simple Intel processor trace decoder based on Intel's [processor-trace](https://github.com/01org/processor-trace) library. It creates bundles of linked PIP, VMCS and TSC packets from a processor trace stream and saves them as as JSON file. Can probably be useful for analyzing VMs using hardware traces.

### Build
VMPT is dependent on [processor-trace](https://github.com/01org/processor-trace) library and `cmake` v2.6+.
```
$ mkdir build && cd build
$ cmake ../
$ make
```

### Test
Start multiple VMs on a Skylake machine and pin them to a single CPU. Get a processor trace snapshot and save it as `snapshot.pt`. Now generate the bundles with VMPT
```
$ ./vmpt snapshot.pt
$ less bundles.json
```

### Licence
Original Copyright holder of processor trace library is Intel. Plese refer `vmpt.c` header.

### Acknowledgements
* Intel folks
* Andi Kleen for [simple-pt](https://github.com/andikleen/simple-pt)
