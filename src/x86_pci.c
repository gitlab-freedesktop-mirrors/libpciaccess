/*
 * Copyright (c) 2018 Damien Zammit
 * Copyright (c) 2017 Joan Lledó
 * Copyright (c) 2009, 2012 Samuel Thibault
 * Heavily inspired from the freebsd, netbsd, and openbsd backends
 * (C) Copyright Eric Anholt 2006
 * (C) Copyright IBM Corporation 2006
 * Copyright (c) 2008 Juan Romero Pardines
 * Copyright (c) 2008 Mark Kettenis
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "x86_pci.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <strings.h>

#include "pciaccess.h"
#include "pciaccess_private.h"

#if defined(__GNU__)

#include <sys/io.h>

int
x86_enable_io(void)
{
    if (!ioperm(0, 0xffff, 1))
        return 0;
    return errno;
}

int
x86_disable_io(void)
{
    if (!ioperm(0, 0xffff, 0))
        return 0;
    return errno;
}

#elif defined(__GLIBC__)

#include <sys/io.h>

static int
x86_enable_io(void)
{
    if (!iopl(3))
        return 0;
    return errno;
}

static int
x86_disable_io(void)
{
    if (!iopl(0))
        return 0;
    return errno;
}

#elif defined(__CYGWIN__)

#include <windows.h>

/* WinIo declarations */
typedef BYTE bool;
typedef struct tagPhysStruct {
    DWORD64 dwPhysMemSizeInBytes;
    DWORD64 pvPhysAddress;
    DWORD64 PhysicalMemoryHandle;
    DWORD64 pvPhysMemLin;
    DWORD64 pvPhysSection;
} tagPhysStruct;

typedef bool  (_stdcall* INITIALIZEWINIO)(void);
typedef void  (_stdcall* SHUTDOWNWINIO)(void);
typedef bool  (_stdcall* GETPORTVAL)(WORD,PDWORD,BYTE);
typedef bool  (_stdcall* SETPORTVAL)(WORD,DWORD,BYTE);
typedef PBYTE (_stdcall* MAPPHYSTOLIN)(tagPhysStruct*);
typedef bool  (_stdcall* UNMAPPHYSMEM)(tagPhysStruct*);

SHUTDOWNWINIO ShutdownWinIo;
GETPORTVAL GetPortVal;
SETPORTVAL SetPortVal;
INITIALIZEWINIO InitializeWinIo;
MAPPHYSTOLIN MapPhysToLin;
UNMAPPHYSMEM UnmapPhysicalMemory;

static int
x86_enable_io(void)
{
    HMODULE lib = NULL;

    if ((GetVersion() & 0x80000000) == 0) {
      /* running on NT, try WinIo version 3 (32 or 64 bits) */
#ifdef WIN64
      lib = LoadLibrary("WinIo64.dll");
#else
      lib = LoadLibrary("WinIo32.dll");
#endif
    }

    if (!lib) {
      fprintf(stderr, "Failed to load WinIo library.\n");
      return 1;
    }

#define GETPROC(n, d) 						\
    n = (d) GetProcAddress(lib, #n); 				\
    if (!n) { 							\
      fprintf(stderr, "Failed to load " #n " function.\n");	\
      return 1; 						\
    }

    GETPROC(InitializeWinIo, INITIALIZEWINIO);
    GETPROC(ShutdownWinIo, SHUTDOWNWINIO);
    GETPROC(GetPortVal, GETPORTVAL);
    GETPROC(SetPortVal, SETPORTVAL);
    GETPROC(MapPhysToLin, MAPPHYSTOLIN);
    GETPROC(UnmapPhysicalMemory, UNMAPPHYSMEM);

#undef GETPROC

    if (!InitializeWinIo()) {
      fprintf(stderr, "Failed to initialize WinIo.\n"
		      "NOTE: WinIo.dll and WinIo.sys must be in the same directory as the executable!\n");
      return 0;
    }

    return 0;
}

static int
x86_disable_io(void)
{
    ShutdownWinIo();
    return 1;
}

static inline uint8_t
inb(uint16_t port)
{
    DWORD pv;

    if (GetPortVal(port, &pv, 1))
      return (uint8_t)pv;
    return 0;
}

static inline uint16_t
inw(uint16_t port)
{
    DWORD pv;

    if (GetPortVal(port, &pv, 2))
      return (uint16_t)pv;
    return 0;
}

static inline uint32_t
inl(uint16_t port)
{
    DWORD pv;

    if (GetPortVal(port, &pv, 4))
        return (uint32_t)pv;
    return 0;
}

static inline void
outb(uint8_t value, uint16_t port)
{
    SetPortVal(port, value, 1);
}

static inline void
outw(uint16_t value, uint16_t port)
{
    SetPortVal(port, value, 2);
}

static inline void
outl(uint32_t value, uint16_t port)
{
    SetPortVal(port, value, 4);
}

#else

#error How to enable IO ports on this system?

#endif

static int
pci_system_x86_conf1_probe(void)
{
    unsigned long sav;
    int res = ENODEV;

    outb(0x01, 0xCFB);
    sav = inl(0xCF8);
    outl(0x80000000, 0xCF8);
    if (inl(0xCF8) == 0x80000000)
	res = 0;
    outl(sav, 0xCF8);

    return res;
}

static int
pci_system_x86_conf1_read(unsigned bus, unsigned dev, unsigned func, pciaddr_t reg, void *data, unsigned size)
{
    unsigned addr = 0xCFC + (reg & 3);
    unsigned long sav;
    int ret = 0;

    if (bus >= 0x100 || dev >= 32 || func >= 8 || reg >= 0x100 || size > 4 || size == 3)
	return EIO;

    sav = inl(0xCF8);
    outl(0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (reg & ~3), 0xCF8);
    /* NOTE: x86 is already LE */
    switch (size) {
	case 1: {
	    uint8_t *val = data;
	    *val = inb(addr);
	    break;
	}
	case 2: {
	    uint16_t *val = data;
	    *val = inw(addr);
	    break;
	}
	case 4: {
	    uint32_t *val = data;
	    *val = inl(addr);
	    break;
	}
    }
    outl(sav, 0xCF8);

    return ret;
}

static int
pci_system_x86_conf1_write(unsigned bus, unsigned dev, unsigned func, pciaddr_t reg, const void *data, unsigned size)
{
    unsigned addr = 0xCFC + (reg & 3);
    unsigned long sav;
    int ret = 0;

    if (bus >= 0x100 || dev >= 32 || func >= 8 || reg >= 0x100 || size > 4 || size == 3)
	return EIO;

    sav = inl(0xCF8);
    outl(0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (reg & ~3), 0xCF8);
    /* NOTE: x86 is already LE */
    switch (size) {
	case 1: {
	    const uint8_t *val = data;
	    outb(*val, addr);
	    break;
	}
	case 2: {
	    const uint16_t *val = data;
	    outw(*val, addr);
	    break;
	}
	case 4: {
	    const uint32_t *val = data;
	    outl(*val, addr);
	    break;
	}
    }
    outl(sav, 0xCF8);

    return ret;
}

static int
pci_system_x86_conf2_probe(void)
{
    outb(0, 0xCFB);
    outb(0, 0xCF8);
    outb(0, 0xCFA);
    if (inb(0xCF8) == 0 && inb(0xCFA) == 0)
	return 0;

    return ENODEV;
}

static int
pci_system_x86_conf2_read(unsigned bus, unsigned dev, unsigned func, pciaddr_t reg, void *data, unsigned size)
{
    unsigned addr = 0xC000 | dev << 8 | reg;
    int ret = 0;

    if (bus >= 0x100 || dev >= 16 || func >= 8 || reg >= 0x100)
	return EIO;

    outb((func << 1) | 0xF0, 0xCF8);
    outb(bus, 0xCFA);
    /* NOTE: x86 is already LE */
    switch (size) {
	case 1: {
	    uint8_t *val = data;
	    *val = inb(addr);
	    break;
	}
	case 2: {
	    uint16_t *val = data;
	    *val = inw(addr);
	    break;
	}
	case 4: {
	    uint32_t *val = data;
	    *val = inl(addr);
	    break;
	}
	default:
	    ret = EIO;
	    break;
    }
    outb(0, 0xCF8);

    return ret;
}

static int
pci_system_x86_conf2_write(unsigned bus, unsigned dev, unsigned func, pciaddr_t reg, const void *data, unsigned size)
{
    unsigned addr = 0xC000 | dev << 8 | reg;
    int ret = 0;

    if (bus >= 0x100 || dev >= 16 || func >= 8 || reg >= 0x100)
	return EIO;

    outb((func << 1) | 0xF0, 0xCF8);
    outb(bus, 0xCFA);
    /* NOTE: x86 is already LE */
    switch (size) {
	case 1: {
	    const uint8_t *val = data;
	    outb(*val, addr);
	    break;
	}
	case 2: {
	    const uint16_t *val = data;
	    outw(*val, addr);
	    break;
	}
	case 4: {
	    const uint32_t *val = data;
	    outl(*val, addr);
	    break;
	}
	default:
	    ret = EIO;
	    break;
    }
    outb(0, 0xCF8);

    return ret;
}

/* Check that this really looks like a PCI configuration. */
static error_t
pci_system_x86_check (void)
{
    int dev;
    uint16_t class, vendor;
    struct pci_device tmpdev = { 0 };

    /* Look on bus 0 for a device that is a host bridge, a VGA card,
     * or an intel or compaq device.  */
    tmpdev.bus = 0;
    tmpdev.func = 0;
    class = 0;
    vendor = 0;

    for (dev = 0; dev < 32; dev++) {
       tmpdev.dev = dev;
       if (pci_device_cfg_read_u16 (&tmpdev, &class, PCI_CLASS_DEVICE))
           continue;
       if (class == PCI_CLASS_BRIDGE_HOST || class == PCI_CLASS_DISPLAY_VGA)
           return 0;
       if (pci_device_cfg_read_u16 (&tmpdev, &vendor, PCI_VENDOR_ID))
           continue;
       if (vendor == PCI_VENDOR_ID_INTEL || class == PCI_VENDOR_ID_COMPAQ)
           return 0;
    }

    return ENODEV;
}

static int
pci_nfuncs(struct pci_device *dev, uint8_t *nfuncs)
{
    uint8_t hdr;
    int err;
    struct pci_device tmpdev = *dev;

    tmpdev.func = 0;

    err = pci_device_cfg_read_u8 (&tmpdev, &hdr, PCI_HDRTYPE);

    if (err)
	return err;

    *nfuncs = hdr & 0x80 ? 8 : 1;
    return err;
}

/**
 * Read a PCI rom.
 */
static error_t
pci_device_x86_read_rom(struct pci_device *dev, void *buffer)
{
    void *bios;
    int memfd;
    struct pci_device_private *d = (struct pci_device_private *)dev;

    memfd = open("/dev/mem", O_RDONLY | O_CLOEXEC);
    if (memfd == -1)
	return errno;

    bios = mmap(NULL, dev->rom_size, PROT_READ, 0, memfd, d->rom_base);
    if (bios == MAP_FAILED) {
	close(memfd);
	return errno;
    }

    memcpy(buffer, bios, dev->rom_size);

    munmap(bios, dev->rom_size);
    close(memfd);

    return 0;
}

/** Returns the number of regions (base address registers) the device has */
static int
pci_device_x86_get_num_regions(uint8_t header_type)
{
    switch (header_type & 0x7f) {
	case 0:
	    return 6;
	case 1:
	    return 2;
	case 2:
	    return 1;
	default:
	    fprintf(stderr,"unknown header type %02x\n", header_type);
	    return 0;
    }
}

/** Masks out the flag bigs of the base address register value */
static uint32_t
get_map_base( uint32_t val )
{
    if (val & 0x01)
	return val & ~0x03;
    else
	return val & ~0x0f;
}

/** Returns the size of a region based on the all-ones test value */
static unsigned
get_test_val_size( uint32_t testval )
{
    unsigned size = 1;

    if (testval == 0)
	return 0;

    /* Mask out the flag bits */
    testval = get_map_base( testval );
    if (!testval)
	return 0;

    while ((testval & 1) == 0) {
	size <<= 1;
	testval >>= 1;
    }

    return size;
}

static int
pci_device_x86_probe(struct pci_device *dev)
{
    uint8_t irq, hdrtype;
    int err, i, bar;

    /* Many of the fields were filled in during initial device enumeration.
     * At this point, we need to fill in regions, rom_size, and irq.
     */

    err = pci_device_cfg_read_u8(dev, &irq, PCI_IRQ);
    if (err)
	return err;
    dev->irq = irq;

    err = pci_device_cfg_read_u8(dev, &hdrtype, PCI_HDRTYPE);
    if (err)
	return err;

    bar = 0x10;
    for (i = 0; i < pci_device_x86_get_num_regions(hdrtype); i++, bar += 4) {
	uint32_t addr, testval;

	/* Get the base address */
	err = pci_device_cfg_read_u32(dev, &addr, bar);
	if (err != 0)
	    continue;

	/* Test write all ones to the register, then restore it. */
	err = pci_device_cfg_write_u32(dev, 0xffffffff, bar);
	if (err != 0)
	    continue;
	pci_device_cfg_read_u32(dev, &testval, bar);
	err = pci_device_cfg_write_u32(dev, addr, bar);

	if (addr & 0x01)
	    dev->regions[i].is_IO = 1;
	if (addr & 0x04)
	    dev->regions[i].is_64 = 1;
	if (addr & 0x08)
	    dev->regions[i].is_prefetchable = 1;

	/* Set the size */
	dev->regions[i].size = get_test_val_size(testval);

	/* Set the base address value */
	if (dev->regions[i].is_64) {
	    uint32_t top;

	    err = pci_device_cfg_read_u32(dev, &top, bar + 4);
	    if (err != 0)
		continue;

	    dev->regions[i].base_addr = ((uint64_t)top << 32) |
					get_map_base(addr);
	    bar += 4;
	    i++;
	} else {
	    dev->regions[i].base_addr = get_map_base(addr);
	}
    }

    /* If it's a VGA device, set up the rom size for read_rom using the
     * 0xc0000 mapping.
     */
    if ((dev->device_class & 0x00ffff00) ==
	((PCIC_DISPLAY << 16) | (PCIS_DISPLAY_VGA << 8)))
    {
	dev->rom_size = 64 * 1024;
    }

    return 0;
}

#if defined(__CYGWIN__)

static int
pci_device_x86_map_range(struct pci_device *dev,
    struct pci_device_mapping *map)
{
    tagPhysStruct phys;

    phys.pvPhysAddress        = (DWORD64)(DWORD32)map->base;
    phys.dwPhysMemSizeInBytes = map->size;

    map->memory = (PDWORD)MapPhysToLin(&phys);
    if (map->memory == NULL)
        return EFAULT;

    return 0;
}

static int
pci_device_x86_unmap_range(struct pci_device *dev,
    struct pci_device_mapping *map)
{
    tagPhysStruct phys;

    phys.pvPhysAddress        = (DWORD64)(DWORD32)map->base;
    phys.dwPhysMemSizeInBytes = map->size;

    if (!UnmapPhysicalMemory(&phys))
        return EFAULT;

    return 0;
}

#else

int
pci_device_x86_map_range(struct pci_device *dev,
    struct pci_device_mapping *map)
{
    int memfd = open("/dev/mem", O_RDWR | O_CLOEXEC);
    int prot = PROT_READ;

    if (memfd == -1)
	return errno;

    if (map->flags & PCI_DEV_MAP_FLAG_WRITABLE)
	prot |= PROT_WRITE;

    map->memory = mmap(NULL, map->size, prot, MAP_SHARED, memfd, map->base);
    close(memfd);
    if (map->memory == MAP_FAILED)
	return errno;

    return 0;
}

int
pci_device_x86_unmap_range(struct pci_device *dev,
    struct pci_device_mapping *map)
{
    return pci_device_generic_unmap_range(dev, map);
}

#endif

static int
pci_device_x86_read_conf1(struct pci_device *dev, void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_read)
{
    int err;

    *bytes_read = 0;
    while (size > 0) {
	int toread = 1 << (ffs(0x4 + (offset & 0x03)) - 1);
	if (toread > size)
	    toread = size;

	err = pci_system_x86_conf1_read(dev->bus, dev->dev, dev->func, offset, data, toread);
	if (err)
	    return err;

	offset += toread;
	data = (char*)data + toread;
	size -= toread;
	*bytes_read += toread;
    }
    return 0;
}

static int
pci_device_x86_read_conf2(struct pci_device *dev, void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_read)
{
    int err;

    *bytes_read = 0;
    while (size > 0) {
	int toread = 1 << (ffs(0x4 + (offset & 0x03)) - 1);
	if (toread > size)
	    toread = size;

	err = pci_system_x86_conf2_read(dev->bus, dev->dev, dev->func, offset, data, toread);
	if (err)
	    return err;

	offset += toread;
	data = (char*)data + toread;
	size -= toread;
	*bytes_read += toread;
    }
    return 0;
}

static int
pci_device_x86_write_conf1(struct pci_device *dev, const void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_written)
{
    int err;

    *bytes_written = 0;
    while (size > 0) {
	int towrite = 4;
	if (towrite > size)
	    towrite = size;
	if (towrite > 4 - (offset & 0x3))
	    towrite = 4 - (offset & 0x3);

	err = pci_system_x86_conf1_write(dev->bus, dev->dev, dev->func, offset, data, towrite);
	if (err)
	    return err;

	offset += towrite;
	data = (const char*)data + towrite;
	size -= towrite;
	*bytes_written += towrite;
    }
    return 0;
}

static int
pci_device_x86_write_conf2(struct pci_device *dev, const void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_written)
{
    int err;

    *bytes_written = 0;
    while (size > 0) {
	int towrite = 4;
	if (towrite > size)
	    towrite = size;
	if (towrite > 4 - (offset & 0x3))
	    towrite = 4 - (offset & 0x3);

	err = pci_system_x86_conf2_write(dev->bus, dev->dev, dev->func, offset, data, towrite);
	if (err)
	    return err;

	offset += towrite;
	data = (const char*)data + towrite;
	size -= towrite;
	*bytes_written += towrite;
    }
    return 0;
}

void
pci_system_x86_destroy(void)
{
    x86_disable_io();
}

struct pci_io_handle *
pci_device_x86_open_legacy_io(struct pci_io_handle *ret,
    struct pci_device *dev, pciaddr_t base, pciaddr_t size)
{
    x86_enable_io();

    ret->base = base;
    ret->size = size;
    ret->is_legacy = 1;

    return ret;
}

void
pci_device_x86_close_io(struct pci_device *dev, struct pci_io_handle *handle)
{
    /* Like in the Linux case, do not disable I/O, as it may be opened several
     * times, and closed fewer times. */
    /* x86_disable_io(); */
}

uint32_t
pci_device_x86_read32(struct pci_io_handle *handle, uint32_t reg)
{
    return inl(reg + handle->base);
}

uint16_t
pci_device_x86_read16(struct pci_io_handle *handle, uint32_t reg)
{
    return inw(reg + handle->base);
}

uint8_t
pci_device_x86_read8(struct pci_io_handle *handle, uint32_t reg)
{
    return inb(reg + handle->base);
}

void
pci_device_x86_write32(struct pci_io_handle *handle, uint32_t reg,
		       uint32_t data)
{
    outl(data, reg + handle->base);
}

void
pci_device_x86_write16(struct pci_io_handle *handle, uint32_t reg,
		       uint16_t data)
{
    outw(data, reg + handle->base);
}

void
pci_device_x86_write8(struct pci_io_handle *handle, uint32_t reg,
		      uint8_t data)
{
    outb(data, reg + handle->base);
}

int
pci_device_x86_map_legacy(struct pci_device *dev, pciaddr_t base,
    pciaddr_t size, unsigned map_flags, void **addr)
{
    struct pci_device_mapping map;
    int err;

    map.base = base;
    map.size = size;
    map.flags = map_flags;
    err = pci_device_x86_map_range(dev, &map);
    *addr = map.memory;

    return err;
}

int
pci_device_x86_unmap_legacy(struct pci_device *dev, void *addr,
    pciaddr_t size)
{
    struct pci_device_mapping map;

    map.size = size;
    map.flags = 0;
    map.memory = addr;

    return pci_device_x86_unmap_range(dev, &map);
}

static const struct pci_system_methods x86_pci_method_conf1 = {
    .destroy = pci_system_x86_destroy,
    .read_rom = pci_device_x86_read_rom,
    .probe = pci_device_x86_probe,
    .map_range = pci_device_x86_map_range,
    .unmap_range = pci_device_x86_unmap_range,
    .read = pci_device_x86_read_conf1,
    .write = pci_device_x86_write_conf1,
    .fill_capabilities = pci_fill_capabilities_generic,
    .open_legacy_io = pci_device_x86_open_legacy_io,
    .close_io = pci_device_x86_close_io,
    .read32 = pci_device_x86_read32,
    .read16 = pci_device_x86_read16,
    .read8 = pci_device_x86_read8,
    .write32 = pci_device_x86_write32,
    .write16 = pci_device_x86_write16,
    .write8 = pci_device_x86_write8,
    .map_legacy = pci_device_x86_map_legacy,
    .unmap_legacy = pci_device_x86_unmap_legacy,
};

static const struct pci_system_methods x86_pci_method_conf2 = {
    .destroy = pci_system_x86_destroy,
    .read_rom = pci_device_x86_read_rom,
    .probe = pci_device_x86_probe,
    .map_range = pci_device_x86_map_range,
    .unmap_range = pci_device_x86_unmap_range,
    .read = pci_device_x86_read_conf2,
    .write = pci_device_x86_write_conf2,
    .fill_capabilities = pci_fill_capabilities_generic,
    .open_legacy_io = pci_device_x86_open_legacy_io,
    .close_io = pci_device_x86_close_io,
    .read32 = pci_device_x86_read32,
    .read16 = pci_device_x86_read16,
    .read8 = pci_device_x86_read8,
    .write32 = pci_device_x86_write32,
    .write16 = pci_device_x86_write16,
    .write8 = pci_device_x86_write8,
    .map_legacy = pci_device_x86_map_legacy,
    .unmap_legacy = pci_device_x86_unmap_legacy,
};

static int pci_probe(void)
{
    pci_sys->methods = &x86_pci_method_conf1;
    if (pci_system_x86_conf1_probe() == 0) {
	if (pci_system_x86_check() == 0)
	    return 1;
    }

    pci_sys->methods = &x86_pci_method_conf2;
    if (pci_system_x86_conf2_probe() == 0) {
	if (pci_system_x86_check() == 0)
	    return 2;
    }

    pci_sys->methods = NULL;
    return 0;
}

_pci_hidden int
pci_system_x86_create(void)
{
    uint8_t nfuncs = 0;
    uint8_t bus, dev, func;
    uint32_t reg = 0, ndevs;
    struct pci_device tmpdev = { 0 };
    struct pci_device_private *device;
    error_t err;
    int confx;

    err = x86_enable_io ();
    if (err)
        return err;

    ndevs = 0;
    for (bus = 0; bus < 256; bus++) {
       tmpdev.bus = bus;
       for (dev = 0; dev < 32; dev++) {
           tmpdev.dev = dev;
           pci_nfuncs(&tmpdev, &nfuncs);
           for (func = 0; func < nfuncs; func++) {
               if (pci_device_cfg_read_u32(&tmpdev, &reg, PCI_VENDOR_ID))
                   continue;
               if (PCI_VENDOR(reg) == PCI_VENDOR_INVALID ||
                   PCI_VENDOR(reg) == 0)
                   continue;
               ndevs++;
           }
       }
    }

    pci_sys = calloc (1, sizeof (struct pci_system));
    if (pci_sys == NULL)
    {
        x86_disable_io ();
        return ENOMEM;
    }

    pci_sys->num_devices = ndevs;
    pci_sys->devices = calloc(ndevs, sizeof(struct pci_device_private));
    if (pci_sys->devices == NULL) {
        x86_disable_io();
        free(pci_sys);
        pci_sys = NULL;
        return ENOMEM;
    }

    confx = pci_probe ();
    if (!confx) {
        x86_disable_io ();
        free (pci_sys);
        pci_sys = NULL;
        return ENODEV;
    }
    else if (confx == 1)
        pci_sys->methods = &x86_pci_method_conf1;
    else
        pci_sys->methods = &x86_pci_method_conf2;

    device = pci_sys->devices;
    for (bus = 0; bus < 256; bus++) {
       tmpdev.bus = bus;
       for (dev = 0; dev < 32; dev++) {
           tmpdev.dev = dev;
           err = pci_nfuncs(&tmpdev, &nfuncs);
           if (err) {
               x86_disable_io ();
               free (pci_sys);
               pci_sys = NULL;
               return ENODEV;
           }
           for (func = 0; func < nfuncs; func++) {
               tmpdev.func = func;
               if (pci_device_cfg_read_u32(&tmpdev, &reg, PCI_VENDOR_ID))
                   continue;
               if (PCI_VENDOR(reg) == PCI_VENDOR_INVALID ||
                   PCI_VENDOR(reg) == 0)
                   continue;
               device->base.domain = device->base.domain_16 = 0;
               device->base.bus = bus;
               device->base.dev = dev;
               device->base.func = func;
               device->base.vendor_id = PCI_VENDOR(reg);
               device->base.device_id = PCI_DEVICE(reg);

               if (pci_device_cfg_read_u32(&tmpdev, &reg, PCI_CLASS))
                   continue;
               device->base.device_class = (reg >> 8) & 0xFF;
               device->base.revision = reg & 0xFF;

               if (pci_device_cfg_read_u32(&tmpdev, &reg, PCI_SUB_VENDOR_ID))
                   continue;
               device->base.subvendor_id = PCI_VENDOR(reg);
               device->base.subdevice_id = PCI_DEVICE(reg);

               device++;
           }
       }
    }

    return 0;
}
