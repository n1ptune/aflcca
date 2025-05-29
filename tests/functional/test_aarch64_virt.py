#!/usr/bin/env python3
#
# Functional test that boots a various Linux systems and checks the
# console output.
#
# Copyright (c) 2022 Linaro Ltd.
#
# Author:
#  Alex Bennée <alex.bennee@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import time
import os
import logging

from qemu_test import BUILD_DIR
from qemu_test import QemuSystemTest, Asset
from qemu_test import exec_command, wait_for_console_pattern
from qemu_test import get_qemu_img, run_cmd
from qemu_test.utils import archive_extract


class Aarch64VirtMachine(QemuSystemTest):
    KERNEL_COMMON_COMMAND_LINE = 'printk.time=0 '
    timeout = 360

    def wait_for_console_pattern(self, success_message, vm=None):
        wait_for_console_pattern(self, success_message,
                                 failure_message='Kernel panic - not syncing',
                                 vm=vm)

    ASSET_ALPINE_ISO = Asset(
        ('https://dl-cdn.alpinelinux.org/'
         'alpine/v3.17/releases/aarch64/alpine-standard-3.17.2-aarch64.iso'),
        '5a36304ecf039292082d92b48152a9ec21009d3a62f459de623e19c4bd9dc027')

    # This tests the whole boot chain from EFI to Userspace
    # We only boot a whole OS for the current top level CPU and GIC
    # Other test profiles should use more minimal boots
    def test_alpine_virt_tcg_gic_max(self):
        iso_path = self.ASSET_ALPINE_ISO.fetch()

        self.set_machine('virt')
        self.vm.set_console()
        kernel_command_line = (self.KERNEL_COMMON_COMMAND_LINE +
                               'console=ttyAMA0')
        self.require_accelerator("tcg")

        self.vm.add_args("-accel", "tcg")
        self.vm.add_args("-cpu", "max,pauth-impdef=on")
        self.vm.add_args("-machine",
                         "virt,acpi=on,"
                         "virtualization=on,"
                         "mte=on,"
                         "gic-version=max,iommu=smmuv3")
        self.vm.add_args("-smp", "2", "-m", "1024")
        self.vm.add_args('-bios', os.path.join(BUILD_DIR, 'pc-bios',
                                               'edk2-aarch64-code.fd'))
        self.vm.add_args("-drive", f"file={iso_path},media=cdrom,format=raw")
        self.vm.add_args('-device', 'virtio-rng-pci,rng=rng0')
        self.vm.add_args('-object', 'rng-random,id=rng0,filename=/dev/urandom')

        self.vm.launch()
        self.wait_for_console_pattern('Welcome to Alpine Linux 3.17')


    ASSET_KERNEL = Asset(
        ('https://fileserver.linaro.org/s/'
         'z6B2ARM7DQT3HWN/download'),
        '12a54d4805cda6ab647cb7c7bbdb16fafb3df400e0d6f16445c1a0436100ef8d')

    def common_aarch64_virt(self, machine):
        """
        Common code to launch basic virt machine with kernel+initrd
        and a scratch disk.
        """
        logger = logging.getLogger('aarch64_virt')

        kernel_path = self.ASSET_KERNEL.fetch()

        self.set_machine('virt')
        self.vm.set_console()
        kernel_command_line = (self.KERNEL_COMMON_COMMAND_LINE +
                               'console=ttyAMA0')
        self.require_accelerator("tcg")
        self.vm.add_args('-cpu', 'max,pauth-impdef=on',
                         '-machine', machine,
                         '-accel', 'tcg',
                         '-kernel', kernel_path,
                         '-append', kernel_command_line)

        # A RNG offers an easy way to generate a few IRQs
        self.vm.add_args('-device', 'virtio-rng-pci,rng=rng0')
        self.vm.add_args('-object',
                         'rng-random,id=rng0,filename=/dev/urandom')

        # Also add a scratch block device
        logger.info('creating scratch qcow2 image')
        image_path = os.path.join(self.workdir, 'scratch.qcow2')
        qemu_img = get_qemu_img(self)
        run_cmd([qemu_img, 'create', '-f', 'qcow2', image_path, '8M'])

        # Add the device
        self.vm.add_args('-blockdev',
                         f"driver=qcow2,file.driver=file,file.filename={image_path},node-name=scratch")
        self.vm.add_args('-device',
                         'virtio-blk-device,drive=scratch')

        self.vm.launch()
        self.wait_for_console_pattern('Welcome to Buildroot')
        time.sleep(0.1)
        exec_command(self, 'root')
        time.sleep(0.1)
        exec_command(self, 'dd if=/dev/hwrng of=/dev/vda bs=512 count=4')
        time.sleep(0.1)
        exec_command(self, 'md5sum /dev/vda')
        time.sleep(0.1)
        exec_command(self, 'cat /proc/interrupts')
        time.sleep(0.1)
        exec_command(self, 'cat /proc/self/maps')
        time.sleep(0.1)

    def test_aarch64_virt_gicv3(self):
        self.common_aarch64_virt("virt,gic_version=3")

    def test_aarch64_virt_gicv2(self):
        self.common_aarch64_virt("virt,gic-version=2")

    # Stack is built with OP-TEE build environment from those instructions:
    # https://linaro.atlassian.net/wiki/spaces/QEMU/pages/29051027459/
    # https://github.com/pbo-linaro/qemu-rme-stack
    ASSET_RME_STACK = Asset(
        ('https://fileserver.linaro.org/s/JX7oNgfDeGXSxcY/'
         'download/rme-stack-op-tee-4.2.0.tar.gz'),
         '1f240f55e8a7a66489c2b7db5d40391e5dcfdd54c82600bd0d4b2145b9a0fbfb')

    # This tests the FEAT_RME cpu implementation, by booting a VM supporting it,
    # and launching a nested VM using it.
    def test_aarch64_virt_rme(self):
        stack_path_tar_gz = self.ASSET_RME_STACK.fetch()
        archive_extract(stack_path_tar_gz, self.workdir)

        self.set_machine('virt')
        self.vm.set_console()
        self.require_accelerator('tcg')

        rme_stack = os.path.join(self.workdir, 'rme-stack')
        kernel = os.path.join(rme_stack, 'out', 'bin', 'Image')
        bios = os.path.join(rme_stack, 'out', 'bin', 'flash.bin')
        drive = os.path.join(rme_stack, 'out-br', 'images', 'rootfs.ext4')

        self.vm.add_args('-accel', 'tcg')
        self.vm.add_args('-cpu', 'max,x-rme=on')
        self.vm.add_args('-m', '2048')
        self.vm.add_args('-M', 'virt,acpi=off,'
                         'virtualization=on,'
                         'secure=on,'
                         'gic-version=3')
        self.vm.add_args('-bios', bios)
        self.vm.add_args('-kernel', kernel)
        self.vm.add_args('-drive', f'format=raw,if=none,file={drive},id=hd0')
        self.vm.add_args('-device', 'virtio-blk-pci,drive=hd0')
        self.vm.add_args('-device', 'virtio-9p-device,fsdev=shr0,mount_tag=shr0')
        self.vm.add_args('-fsdev', f'local,security_model=none,path={rme_stack},id=shr0')
        self.vm.add_args('-device', 'virtio-net-pci,netdev=net0')
        self.vm.add_args('-netdev', 'user,id=net0')
        self.vm.add_args('-append', 'root=/dev/vda')

        self.vm.launch()
        self.wait_for_console_pattern('Welcome to Buildroot')
        time.sleep(0.1)
        exec_command(self, 'root')
        time.sleep(0.1)

        # We now boot the (nested) guest VM
        exec_command(self,
                     'qemu-system-aarch64 -M virt,gic-version=3 '
                     '-cpu host -enable-kvm -m 512M '
                     '-M confidential-guest-support=rme0 '
                     '-object rme-guest,id=rme0,measurement-algo=sha512 '
                     '-device virtio-net-pci,netdev=net0,romfile= '
                     '-netdev user,id=net0 '
                     '-kernel /mnt/out/bin/Image '
                     '-initrd /mnt/out-br/images/rootfs.cpio '
                     '-serial stdio')
        # Detect Realm activation during boot.
        self.wait_for_console_pattern('SMC_RMI_REALM_ACTIVATE')
        # Wait for boot to complete.
        self.wait_for_console_pattern('Welcome to Buildroot')

if __name__ == '__main__':
    QemuSystemTest.main()
