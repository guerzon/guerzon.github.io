---
title: "Demystifying Linux primitives - building containers from scratch"
date: 2022-02-11
layout: single
tags:
  - linux
  - kernel
  - containers
---

I was recently asked by a former colleague, a backend developer trying to learning Docker, what the differences are between virtual machines and containers. I knew the answer by heart, having beein working on various virtualization products (VMWare ESXi/vSphere, VMWare Workstation, Virtualbox, and KVM which is also used by AWS) and container tech (Docker, podman, Kubernetes). Trying to explain the concept as simple as I could without losing important details, I told them something to the tune of:

- With a virtual machine, you have an instance of an operating system wherein you allocate physical resources to it such as CPU and memory. You do this using a piece of software called a hypervisor, which provides a complete isolation between the operating systems instances.
- Whereas a container is just a bunch of processes which are controlled and grouped using Linux kernel features such as `cgroups` and `namespaces`. You do this with a host, which is an instance of an operating system. So containers are just processes, and you can even see what's running "inside" them when you run `ps` commands in the host.

That was the end of it. Quite straightforward, really. But then I also asked myself how `cgroups` and `namespaces` actually work in the background.

---

Come back soon for part 2! ;)

\- [Lester](https://twitter.com/pidnull)
