# Divinity
Divinity is a multi-purpose project windows kernel framework for **driver mapping, communication and Dll injection**. <br />
I've used **divinity-mapper** for multiple projects like my upcoming **Sorana Spoofer**, <a href="https://github.com/MicrosoftARMAssembler/Nocturnal-HV">**Nocturnal HV**</a>, <a href="https://github.com/MicrosoftARMAssembler/Divinity-Fortnite-Internal/tree/main">**Divinity Internal**</a>, e.g.. <br />
It's personally my **favorite mapper** I've developed because it lets you perform operations that would be normally **detected** in your driver. <br />

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#mapper">Mapper</a>
    </li>
    <li>
      <a href="#injector">Injector</a>
    </li>
    <li>
      <a href="#driver">Driver</a>
    </li>
    <li><a href="#documentation">Roadmap</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#conclusion">Conclusion</a></li>
  </ol>
</details>

# What makes Divinity different?
Divinity was designed around **legitimate backed memory**, allowing it to perform operations that public projects cannot do because of anti-cheats. <br />
The mapper allocates inside by splitting large pages backed by ```ntoskrnl.exe```, allowing us to **bypass memory range and stack walking checks**. <br />
The driver allocates process memory by injecting **mirrored PML4** entries into the **target, clone, and client address spaces**. <br />

<details>
<summary><b>Mapper</b></summary> - <a href="./divinity-mapper/">View Code</a>

  The mapper searches the ```ntoskrnl.exe``` for **unused large pages inside existing sections**. <br />
  When the unused large page is found the mapper **splits that large page into 4KB pages**. <br />
  This gives the mapped driver **backed executable memory**. <br />

  # Why Large Page Splitting?
Anti-cheats detect manually mapped drivers by scanning for executable memory that isn't backed by a known module.
By splitting unused large pages inside ntoskrnl.exe's existing sections, the allocation inherits ntoskrnl's backing — making it appear as legitimate kernel module memory rather than an anonymous allocation.
This defeats two common checks:

* Memory range checks — the address falls within ntoskrnl's known range
* Stack walking — execution traces back to a trusted module
  
</details>

<details>
  <summary><b>Injector</b></summary> - <a href="./divinity-injector/">View Code</a>

  The injector manual maps a Dll into the target process through the **driver's hyperspace framework**. <br />
  It allocates memory through hyperspace, resolves imports, maps missing dependencies, and executes <b>DllMain through thread injection</b>. <br />

  The hyperspace **clones the target virtual address space** and **exposes the mapped pages** into the client process. <br />
  Usermode **writes to the addresses directly**, while the **driver mirrors the backing page-table entries** into the target process. <br />
  This gives the **injector a stable way to build the Dll image** **without constantly copying buffers** through small read and write requests. <br />

# Why Hyperspace?
Traditional injection copies buffers repeatedly through read/write kernel requests, each one is an observable operation that anti-cheats can hook or count.
By injecting mirrored PML4 entries, usermode writes directly to the target's backing pages without any API calls in the hot path.

* MmCopyMemory hooks — no copy APIs are called
* Write frequency — the buffer is built in one direct segment
* Page fault monitoring — pages are already mapped, no faults triggered

<b>Allocation Caution</b><br />
**Portal allocations use injected PML4 entries** and should be freed through <b>free_virtual</b>. <br />
If the **allocation is not released**, the stale PML4E can cause **bugchecks** after the **game closes**. <br />

# DllMain Execution
  The injector **finds a target thread, suspends it, saves the current context, writes a small execution stub**, and replaces <b>Rip</b> with the stub address. <br />
  The stub calls the mapped DLL's <b>DllMain</b>, reports execution status through the added <b>.exec</b> section, then jumps back to the original instruction pointer. <br />
  The injector watches the status fields and **retries if the thread exits or times out during execution**. <br />

</details>

<details>
  <summary><b>Driver</b></summary> - <a href="./divinity-driver/">View Code</a>

  The **driver is mapped into backed executable memory**, so it **can use <b>PsCreateSystemThread</b>** for communication **without needing a custom hidden thread**. <br />
  We use a **WNF state change subscription to receive the intialization data** from the client process. <br />
  The **WNF callback maps the client communication buffer**, references the request and response semaphores, and initializes the shared control block. <br />
  After that, the system thread waits on the request semaphore, handles commands, and releases the response semaphore when each **request completes**. <br />
  
# Why WNF?
Most drivers communicate via IOCTLs or named kernel threads, both are scanned by anti-cheats looking for device objects and threads executing from unknown modules.
By using WNF state change subscriptions, callbacks appear as normal Windows notification activity with no device object or thread to find.

* Thread scanning — no kernel thread is created from an unsigned module
* Device object checks — no suspicious IOCTL device to enumerate
* Hook detection — WNF is a legitimate Windows mechanism, callbacks blend in

</details>

## Documentation
<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/b5b1adcc-1d32-4616-818e-a7c572608c00" />
<img width="1950" height="1391" alt="image (1)" src="https://github.com/user-attachments/assets/e473390d-c4e7-4475-ba5b-d2688fcbdbb6" />

## Roadmap
- [x] Add large page backed allocation
- [x] Add WNF client initialization
- [x] Add hyperspace process cloning
- [x] Add portal allocations
- [x] Add recursive dependency mapping
- [x] Add thread context execution
- [x] Add screenshots for mapper, and injector
- [ ] Add portal allocation freeing before process closes ( will cause blue screens )

## Conclusion
Divinity is a **three piece framework** for **manual mapping kernel drivers through large pages, and manual mapping Dlls through hyperspacing**. <br />
The most important pieces are the large page allocator, hyperspace portal, and thread context hooking. <br />
I love this project for the angle it takes on legitimate memory allocation and how it proved it's worthness through stress testing on multiple projects.  <br />
