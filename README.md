# Xenpwn

Xenpwn is a toolkit for memory access tracing using hardware assisted virtualization. 

It runs as a normal user space application inside the management domain (dom0) of a Xen hypervisor and can be used to trace any memory accesses performed by another VM running on the same hypervisor. The toolkit uses [libvmi](http://libvmi.com/) for interaction with the Xen hypervisor API and relies on [simutrace](https://github.com/simutrace/simutrace) for efficient storage of memory traces. Xenpwn was used to discover double fetch vulnerabilities in the inter domain communication of the Xen hypervisor resulting in [XSA 155](http://xenbits.xen.org/xsa/advisory-155.html). Further research on identifying double fetches in other software is still ongoing. 

This code was created as part of my master thesis ["Tracing Privileged Memory Accesses to Discover Software Vulnerabilities"](https://os.itec.kit.edu/downloads/ma_2015_wilhelm_felix__discover_software_vulnerabilities.pdf) at Karlsruhe Institute of Technology (KIT). The thesis includes a detailed discussion of the design, architecture and implementation. 

Xenpwn is heavily inspired by the [Bochspwn](http://vexillium.org/dl.php?bochspwn.pdf) research done by [j00ru](http://j00ru.vexillium.org/) and [gynvael](http://gynvael.coldwind.pl/).

## License

MIT License

## Build Instructions

* Install Xen (tested with version >=4.4)
* Install libvmi (http://libvmi.com/)
* Install simutrace (http://simutrace.org/)
* Install capstone engine (http://www.capstone-engine.org/)
* Build Xenpwn:
```
mkdir build
cd build; cmake ../;
make
```


## Extending Xenpwn

The codebase can be separated into target independent and target specific code.
Wheras target independent code should be largely reusable for other targets, the target specific code needs to be adapted. This repository currently only contains code for analyzing the Xen hypervisor.

For supporting a new target the following components need to be developed:

* Identification of physical memory pages: Xenpwn is not well suited to trace **all** memory accesses in a system due to the large active overhead introduced by VM exits. For acceptable performance only a small subset of physical memory addresses should be traced. For the use case described in my thesis, these are the memory pages used for inter-domain communication. (Current implementation is in xentrace.cc)
* Trigger on page updates: Depending on your use case the set of watched pages might change during runtime. This can be implemented by settinglibvmi breakpoints at the right code locations (Current implementation xentrace.cc: reparse_grant_table)
* Decide if a memory access is interesting (xentrace.cc xen_trace_event). The actual trace event handler should be adapted to only store memory accesses that are interesting for your use case.






