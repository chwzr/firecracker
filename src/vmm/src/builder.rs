// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
#[cfg(feature = "gdb")]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use event_manager::SubscriberOps;
use linux_loader::cmdline::Cmdline as LoaderKernelCmdline;
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};
use utils::time::TimestampUs;
#[cfg(target_arch = "aarch64")]
use vm_memory::GuestAddress;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

#[cfg(target_arch = "aarch64")]
use crate::Vcpu;
use crate::arch::{self, ConfigurationError, configure_system_for_boot, load_kernel};
#[cfg(target_arch = "aarch64")]
use crate::construct_kvm_mpidrs;
use crate::cpu_config::templates::{GetCpuTemplate, GetCpuTemplateError, GuestConfigError};
#[cfg(target_arch = "x86_64")]
use crate::device_manager;
use crate::device_manager::pci_mngr::PciManagerError;
use crate::device_manager::{
    AttachDeviceError, DeviceManager, DeviceManagerCreateError, DevicePersistError,
    DeviceRestoreArgs,
};
use crate::devices::acpi::vmgenid::VmGenIdError;
use crate::devices::virtio::balloon::Balloon;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::net::Net;
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::vsock::{Vsock, VsockUnixBackend};
#[cfg(feature = "gdb")]
use crate::gdb;
use crate::initrd::{InitrdConfig, InitrdError};
use crate::logger::{debug, error};
use crate::persist::{GuestRegionUffdMapping, MemoryDescriptor, MicrovmState, MicrovmStateError};
use crate::resources::VmResources;
use crate::seccomp::BpfThreadMap;
use crate::snapshot::Persist;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::MachineConfigError;
use crate::vstate::kvm::{Kvm, KvmError};
use crate::vstate::memory::GuestRegionMmap;
#[cfg(target_arch = "aarch64")]
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vcpu::VcpuError;
use crate::vstate::vm::{Vm, VmError};
use crate::{EventManager, Vmm, VmmError};

/// Errors associated with starting the instance.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartMicrovmError {
    /// Unable to attach block device to Vmm: {0}
    AttachBlockDevice(io::Error),
    /// Could not attach device: {0}
    AttachDevice(#[from] AttachDeviceError),
    /// Unable to create/open the memory backing file: {0}
    BackingMemoryFile(io::Error),
    /// System configuration error: {0}
    ConfigureSystem(#[from] ConfigurationError),
    /// Failed to create device manager: {0}
    CreateDeviceManager(#[from] DeviceManagerCreateError),
    /// Failed to create guest config: {0}
    CreateGuestConfig(#[from] GuestConfigError),
    /// Cannot create network device: {0}
    CreateNetDevice(crate::devices::virtio::net::NetError),
    /// Cannot create RateLimiter: {0}
    CreateRateLimiter(io::Error),
    /// Error creating legacy device: {0}
    #[cfg(target_arch = "x86_64")]
    CreateLegacyDevice(device_manager::legacy::LegacyDeviceError),
    /// Error creating VMGenID device: {0}
    CreateVMGenID(VmGenIdError),
    /// Error enabling PCIe support: {0}
    EnablePciDevices(#[from] PciManagerError),
    /// Error enabling pvtime on vcpu: {0}
    #[cfg(target_arch = "aarch64")]
    EnablePVTime(crate::arch::VcpuArchError),
    /// Invalid Memory Configuration: {0}
    GuestMemory(crate::vstate::memory::MemoryError),
    /// Error with initrd initialization: {0}.
    Initrd(#[from] InitrdError),
    /// Internal error while starting microVM: {0}
    Internal(#[from] VmmError),
    /// Failed to get CPU template: {0}
    GetCpuTemplate(#[from] GetCpuTemplateError),
    /// Invalid kernel command line: {0}
    KernelCmdline(String),
    /// Kvm error: {0}
    Kvm(#[from] KvmError),
    /// Cannot load command line string: {0}
    LoadCommandline(linux_loader::loader::Error),
    /// Cannot start microvm without kernel configuration.
    MissingKernelConfig,
    /// Cannot start microvm without guest mem_size config.
    MissingMemSizeConfig,
    /// No seccomp filter for thread category: {0}
    MissingSeccompFilters(String),
    /// Failed to create an UFFD Builder: {0}
    CreateUffdBuilder(userfaultfd::Error),
    /// Unable to connect to UDS in order to send information regarding handling guest memory page-fault events: {0}
    UdsConnection(io::Error),
    /// Failed to register guest memory regions to UFFD: {0}
    UffdMemoryRegionsRegister(userfaultfd::Error),
    /// Failed to send guest memory layout and path to user fault FD used to handle guest memory page faults: {0}
    UffdSend(kvm_ioctls::Error),
    /// Failed to get the memfd from the uffd socket
    NoMemFdReceived,
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file: {0}
    OpenBlockDevice(io::Error),
    /// Cannot restore microvm state: {0}
    RestoreMicrovmState(MicrovmStateError),
    /// Cannot set vm resources: {0}
    SetVmResources(MachineConfigError),
    /// Cannot create the entropy device: {0}
    CreateEntropyDevice(crate::devices::virtio::rng::EntropyError),
    /// Failed to allocate guest resource: {0}
    AllocateResources(#[from] vm_allocator::Error),
    /// Error starting GDB debug session
    #[cfg(feature = "gdb")]
    GdbServer(gdb::target::GdbTargetError),
    /// Error cloning Vcpu fds
    #[cfg(feature = "gdb")]
    VcpuFdCloneError(#[from] crate::vstate::vcpu::CopyKvmFdError),
    /// Error with the Vm object: {0}
    Vm(#[from] VmError),
}

/// It's convenient to automatically convert `linux_loader::cmdline::Error`s
/// to `StartMicrovmError`s.
impl std::convert::From<linux_loader::cmdline::Error> for StartMicrovmError {
    fn from(err: linux_loader::cmdline::Error) -> StartMicrovmError {
        StartMicrovmError::KernelCmdline(err.to_string())
    }
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// The built microVM and all the created vCPUs start off in the paused state.
/// To boot the microVM and run those vCPUs, `Vmm::resume_vm()` needs to be
/// called.
pub fn build_microvm_for_boot(
    instance_info: &InstanceInfo,
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    // Timestamp for measuring microVM boot duration.
    let request_ts = TimestampUs::default();

    let boot_config = vm_resources
        .boot_source
        .builder
        .as_ref()
        .ok_or(StartMicrovmError::MissingKernelConfig)?;

    let track_dirty_pages = vm_resources.machine_config.track_dirty_pages;

    let (guest_memory, memory_descriptor, _file) =
        if let Some(ref backend_config) = vm_resources.memory_backend {
            match backend_config.backend_type {
                crate::vmm_config::snapshot::MemBackendType::File => {
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&backend_config.backend_path)
                        .map_err(StartMicrovmError::BackingMemoryFile)?;
                    file.set_len((vm_resources.machine_config.mem_size_mib * 1024 * 1024) as u64)
                        .map_err(|e| {
                            error!("Failed to set backing memory file size: {}", e);
                            StartMicrovmError::BackingMemoryFile(e)
                        })?;

                    let file = Arc::new(file);

                    (
                        create_guest_memory(
                            vm_resources.machine_config.mem_size_mib,
                            Some(file.clone()),
                            track_dirty_pages,
                        )?,
                        Some(MemoryDescriptor::File(file)),
                        None,
                    )
                }
                crate::vmm_config::snapshot::MemBackendType::Uffd => {
                    let (mem, uffd, file) = create_uffd_guest_memory(
                        vm_resources.machine_config.mem_size_mib,
                        backend_config.backend_path.as_path(),
                        track_dirty_pages,
                    )?;

                    (mem, Some(MemoryDescriptor::Uffd(uffd)), Some(file))
                }
            }
        } else {
            (
                create_guest_memory(
                    vm_resources.machine_config.mem_size_mib,
                    None,
                    track_dirty_pages,
                )?,
                None,
                None,
            )
        };

    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut boot_cmdline = boot_config.cmdline.clone();

    let cpu_template = vm_resources
        .machine_config
        .cpu_template
        .get_cpu_template()?;

    let kvm = Kvm::new(cpu_template.kvm_capabilities.clone())?;
    // Set up Kvm Vm and register memory regions.
    // Build custom CPU config if a custom template is provided.
    let mut vm = Vm::new(&kvm)?;
    let (mut vcpus, vcpus_exit_evt) = vm.create_vcpus(vm_resources.machine_config.vcpu_count)?;
    vm.register_memory_regions(guest_memory)?;

    let mut device_manager = DeviceManager::new(event_manager, &vcpus_exit_evt, &vm)?;

    let vm = Arc::new(vm);

    let entry_point = load_kernel(&boot_config.kernel_file, vm.guest_memory())?;
    let initrd = InitrdConfig::from_config(boot_config, vm.guest_memory())?;

    #[cfg(feature = "gdb")]
    let (gdb_tx, gdb_rx) = mpsc::channel();
    #[cfg(feature = "gdb")]
    vcpus
        .iter_mut()
        .for_each(|vcpu| vcpu.attach_debug_info(gdb_tx.clone()));
    #[cfg(feature = "gdb")]
    let vcpu_fds = vcpus
        .iter()
        .map(|vcpu| vcpu.copy_kvm_vcpu_fd(&vm))
        .collect::<Result<Vec<_>, _>>()?;

    if vm_resources.pci_enabled {
        device_manager.enable_pci(&vm)?;
    } else {
        boot_cmdline.insert("pci", "off")?;
    }

    // The boot timer device needs to be the first device attached in order
    // to maintain the same MMIO address referenced in the documentation
    // and tests.
    if vm_resources.boot_timer {
        device_manager.attach_boot_timer_device(&vm, request_ts)?;
    }

    if let Some(balloon) = vm_resources.balloon.get() {
        attach_balloon_device(
            &mut device_manager,
            &vm,
            &mut boot_cmdline,
            balloon,
            event_manager,
        )?;
    }

    attach_block_devices(
        &mut device_manager,
        &vm,
        &mut boot_cmdline,
        vm_resources.block.devices.iter(),
        event_manager,
    )?;
    attach_net_devices(
        &mut device_manager,
        &vm,
        &mut boot_cmdline,
        vm_resources.net_builder.iter(),
        event_manager,
    )?;

    if let Some(unix_vsock) = vm_resources.vsock.get() {
        attach_unixsock_vsock_device(
            &mut device_manager,
            &vm,
            &mut boot_cmdline,
            unix_vsock,
            event_manager,
        )?;
    }

    if let Some(entropy) = vm_resources.entropy.get() {
        attach_entropy_device(
            &mut device_manager,
            &vm,
            &mut boot_cmdline,
            entropy,
            event_manager,
        )?;
    }

    #[cfg(target_arch = "aarch64")]
    device_manager.attach_legacy_devices_aarch64(&vm, event_manager, &mut boot_cmdline)?;

    device_manager.attach_vmgenid_device(vm.guest_memory(), &vm)?;

    #[cfg(target_arch = "aarch64")]
    if vcpus[0].kvm_vcpu.supports_pvtime() {
        setup_pvtime(&mut vm.resource_allocator(), &mut vcpus)?;
    } else {
        log::warn!("Vcpus do not support pvtime, steal time will not be reported to guest");
    }

    configure_system_for_boot(
        &kvm,
        &vm,
        &mut device_manager,
        vcpus.as_mut(),
        &vm_resources.machine_config,
        &cpu_template,
        entry_point,
        &initrd,
        boot_cmdline,
    )?;

    let vmm = Vmm {
        events_observer: Some(std::io::stdin()),
        instance_info: instance_info.clone(),
        shutdown_exit_code: None,
        kvm,
        vm,
        memory_descriptor,
        vcpus_handles: Vec::new(),
        vcpus_exit_evt,
        device_manager,
    };

    let vmm = Arc::new(Mutex::new(vmm));

    #[cfg(feature = "gdb")]
    if let Some(gdb_socket_path) = &vm_resources.machine_config.gdb_socket_path {
        gdb::gdb_thread(
            vmm.clone(),
            vcpu_fds,
            gdb_rx,
            entry_point.entry_addr,
            gdb_socket_path,
        )
        .map_err(StartMicrovmError::GdbServer)?;
    } else {
        debug!("No GDB socket provided not starting gdb server.");
    }

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    vmm.lock()
        .unwrap()
        .start_vcpus(
            vcpus,
            seccomp_filters
                .get("vcpu")
                .ok_or_else(|| StartMicrovmError::MissingSeccompFilters("vcpu".to_string()))?
                .clone(),
        )
        .map_err(VmmError::VcpuStart)?;

    // Load seccomp filters for the VMM thread.
    // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
    // altogether is the desired behaviour.
    // Keep this as the last step before resuming vcpus.
    crate::seccomp::apply_filter(
        seccomp_filters
            .get("vmm")
            .ok_or_else(|| StartMicrovmError::MissingSeccompFilters("vmm".to_string()))?,
    )
    .map_err(VmmError::SeccompFilters)?;

    event_manager.add_subscriber(vmm.clone());

    Ok(vmm)
}

/// Builds and boots a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
pub fn build_and_boot_microvm(
    instance_info: &InstanceInfo,
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    debug!("event_start: build microvm for boot");
    let vmm = build_microvm_for_boot(instance_info, vm_resources, event_manager, seccomp_filters)?;
    debug!("event_end: build microvm for boot");
    // The vcpus start off in the `Paused` state, let them run.
    debug!("event_start: boot microvm");
    vmm.lock().unwrap().resume_vm()?;
    debug!("event_end: boot microvm");
    Ok(vmm)
}

/// Error type for [`build_microvm_from_snapshot`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BuildMicrovmFromSnapshotError {
    /// Failed to create microVM and vCPUs: {0}
    CreateMicrovmAndVcpus(#[from] StartMicrovmError),
    /// Could not access KVM: {0}
    KvmAccess(#[from] vmm_sys_util::errno::Error),
    /// Error configuring the TSC, frequency not present in the given snapshot.
    TscFrequencyNotPresent,
    #[cfg(target_arch = "x86_64")]
    /// Could not get TSC to check if TSC scaling was required with the snapshot: {0}
    GetTsc(#[from] crate::arch::GetTscError),
    #[cfg(target_arch = "x86_64")]
    /// Could not set TSC scaling within the snapshot: {0}
    SetTsc(#[from] crate::arch::SetTscError),
    /// Failed to restore microVM state: {0}
    RestoreState(#[from] crate::vstate::vm::ArchVmError),
    /// Failed to update microVM configuration: {0}
    VmUpdateConfig(#[from] MachineConfigError),
    /// Failed to restore MMIO device: {0}
    RestoreMmioDevice(#[from] MicrovmStateError),
    /// Failed to emulate MMIO serial: {0}
    EmulateSerialInit(#[from] crate::EmulateSerialInitError),
    /// Failed to start vCPUs as no vCPU seccomp filter found.
    MissingVcpuSeccompFilters,
    /// Failed to start vCPUs: {0}
    StartVcpus(#[from] crate::StartVcpusError),
    /// Failed to restore vCPUs: {0}
    RestoreVcpus(#[from] VcpuError),
    /// Failed to apply VMM secccomp filter as none found.
    MissingVmmSeccompFilters,
    /// Failed to apply VMM secccomp filter: {0}
    SeccompFiltersInternal(#[from] crate::seccomp::InstallationError),
    /// Failed to restore devices: {0}
    RestoreDevices(#[from] DevicePersistError),
}

/// Builds and starts a microVM based on the provided MicrovmState.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
#[allow(clippy::too_many_arguments)]
pub fn build_microvm_from_snapshot(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    microvm_state: MicrovmState,
    guest_memory: Vec<GuestRegionMmap>,
    memory_descriptor: Option<MemoryDescriptor>,
    seccomp_filters: &BpfThreadMap,
    vm_resources: &mut VmResources,
) -> Result<Arc<Mutex<Vmm>>, BuildMicrovmFromSnapshotError> {
    // Build Vmm.
    debug!("event_start: build microvm from snapshot");

    let kvm = Kvm::new(microvm_state.kvm_state.kvm_cap_modifiers.clone())
        .map_err(StartMicrovmError::Kvm)?;
    // Set up Kvm Vm and register memory regions.
    // Build custom CPU config if a custom template is provided.
    let mut vm = Vm::new(&kvm).map_err(StartMicrovmError::Vm)?;

    let (mut vcpus, vcpus_exit_evt) = vm
        .create_vcpus(vm_resources.machine_config.vcpu_count)
        .map_err(StartMicrovmError::Vm)?;

    vm.register_memory_regions(guest_memory)
        .map_err(StartMicrovmError::Vm)?;

    #[cfg(target_arch = "x86_64")]
    {
        // Scale TSC to match, extract the TSC freq from the state if specified
        if let Some(state_tsc) = microvm_state.vcpu_states[0].tsc_khz {
            // Scale the TSC frequency for all VCPUs. If a TSC frequency is not specified in the
            // snapshot, by default it uses the host frequency.
            if vcpus[0].kvm_vcpu.is_tsc_scaling_required(state_tsc)? {
                for vcpu in &vcpus {
                    vcpu.kvm_vcpu.set_tsc_khz(state_tsc)?;
                }
            }
        }
    }

    // Restore vcpus kvm state.
    for (vcpu, state) in vcpus.iter_mut().zip(microvm_state.vcpu_states.iter()) {
        vcpu.kvm_vcpu
            .restore_state(state)
            .map_err(VcpuError::VcpuResponse)
            .map_err(BuildMicrovmFromSnapshotError::RestoreVcpus)?;
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mpidrs = construct_kvm_mpidrs(&microvm_state.vcpu_states);
        // Restore kvm vm state.
        vm.restore_state(&mpidrs, &microvm_state.vm_state)?;
    }

    // Restore kvm vm state.
    #[cfg(target_arch = "x86_64")]
    vm.restore_state(&microvm_state.vm_state)?;

    // Restore the boot source config paths.
    vm_resources.boot_source.config = microvm_state.vm_info.boot_source;

    let vm = Arc::new(vm);

    // Restore devices states.
    // Restoring VMGenID injects an interrupt in the guest to notify it about the new generation
    // ID. As a result, we need to restore DeviceManager after restoring the KVM state, otherwise
    // the injected interrupt will be overwritten.
    let device_ctor_args = DeviceRestoreArgs {
        mem: vm.guest_memory(),
        vm: &vm,
        event_manager,
        vm_resources,
        instance_id: &instance_info.id,
        restored_from_file: memory_descriptor.is_none(),
        vcpus_exit_evt: &vcpus_exit_evt,
    };
    #[allow(unused_mut)]
    let mut device_manager =
        DeviceManager::restore(device_ctor_args, &microvm_state.device_states)?;

    let mut vmm = Vmm {
        events_observer: Some(std::io::stdin()),
        instance_info: instance_info.clone(),
        shutdown_exit_code: None,
        kvm,
        vm,
        memory_descriptor,
        vcpus_handles: Vec::new(),
        vcpus_exit_evt,
        device_manager,
    };

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    vmm.start_vcpus(
        vcpus,
        seccomp_filters
            .get("vcpu")
            .ok_or(BuildMicrovmFromSnapshotError::MissingVcpuSeccompFilters)?
            .clone(),
    )?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    // Load seccomp filters for the VMM thread.
    // Keep this as the last step of the building process.
    crate::seccomp::apply_filter(
        seccomp_filters
            .get("vmm")
            .ok_or(BuildMicrovmFromSnapshotError::MissingVmmSeccompFilters)?,
    )?;
    debug!("event_end: build microvm from snapshot");

    Ok(vmm)
}

/// 64 bytes due to alignment requirement in 3.1 of https://www.kernel.org/doc/html/v5.8/virt/kvm/devices/vcpu.html#attribute-kvm-arm-vcpu-pvtime-ipa
#[cfg(target_arch = "aarch64")]
const STEALTIME_STRUCT_MEM_SIZE: u64 = 64;

/// Helper method to allocate steal time region
#[cfg(target_arch = "aarch64")]
fn allocate_pvtime_region(
    resource_allocator: &mut ResourceAllocator,
    vcpu_count: usize,
    policy: vm_allocator::AllocPolicy,
) -> Result<GuestAddress, StartMicrovmError> {
    let size = STEALTIME_STRUCT_MEM_SIZE * vcpu_count as u64;
    let addr = resource_allocator
        .allocate_system_memory(size, STEALTIME_STRUCT_MEM_SIZE, policy)
        .map_err(StartMicrovmError::AllocateResources)?;
    Ok(GuestAddress(addr))
}

/// Sets up pvtime for all vcpus
#[cfg(target_arch = "aarch64")]
fn setup_pvtime(
    resource_allocator: &mut ResourceAllocator,
    vcpus: &mut [Vcpu],
) -> Result<(), StartMicrovmError> {
    // Alloc sys mem for steal time region
    let pvtime_mem: GuestAddress = allocate_pvtime_region(
        resource_allocator,
        vcpus.len(),
        vm_allocator::AllocPolicy::LastMatch,
    )?;

    // Register all vcpus with pvtime device
    for (i, vcpu) in vcpus.iter_mut().enumerate() {
        vcpu.kvm_vcpu
            .enable_pvtime(GuestAddress(
                pvtime_mem.0 + i as u64 * STEALTIME_STRUCT_MEM_SIZE,
            ))
            .map_err(StartMicrovmError::EnablePVTime)?;
    }

    Ok(())
}

fn attach_entropy_device(
    device_manager: &mut DeviceManager,
    vm: &Arc<Vm>,
    cmdline: &mut LoaderKernelCmdline,
    entropy_device: &Arc<Mutex<Entropy>>,
    event_manager: &mut EventManager,
) -> Result<(), AttachDeviceError> {
    let id = entropy_device
        .lock()
        .expect("Poisoned lock")
        .id()
        .to_string();

    event_manager.add_subscriber(entropy_device.clone());
    device_manager.attach_virtio_device(vm, id, entropy_device.clone(), cmdline, false)
}

fn attach_block_devices<'a, I: Iterator<Item = &'a Arc<Mutex<Block>>> + Debug>(
    device_manager: &mut DeviceManager,
    vm: &Arc<Vm>,
    cmdline: &mut LoaderKernelCmdline,
    blocks: I,
    event_manager: &mut EventManager,
) -> Result<(), StartMicrovmError> {
    for block in blocks {
        let (id, is_vhost_user) = {
            let locked = block.lock().expect("Poisoned lock");
            if locked.root_device() {
                match locked.partuuid() {
                    Some(partuuid) => cmdline.insert_str(format!("root=PARTUUID={}", partuuid))?,
                    None => cmdline.insert_str("root=/dev/vda")?,
                }
                match locked.read_only() {
                    true => cmdline.insert_str("ro")?,
                    false => cmdline.insert_str("rw")?,
                }
            }
            (locked.id().to_string(), locked.is_vhost_user())
        };
        // The device mutex mustn't be locked here otherwise it will deadlock.
        event_manager.add_subscriber(block.clone());
        device_manager.attach_virtio_device(vm, id, block.clone(), cmdline, is_vhost_user)?;
    }
    Ok(())
}

fn attach_net_devices<'a, I: Iterator<Item = &'a Arc<Mutex<Net>>> + Debug>(
    device_manager: &mut DeviceManager,
    vm: &Arc<Vm>,
    cmdline: &mut LoaderKernelCmdline,
    net_devices: I,
    event_manager: &mut EventManager,
) -> Result<(), StartMicrovmError> {
    for net_device in net_devices {
        let id = net_device.lock().expect("Poisoned lock").id().clone();
        event_manager.add_subscriber(net_device.clone());
        // The device mutex mustn't be locked here otherwise it will deadlock.
        device_manager.attach_virtio_device(vm, id, net_device.clone(), cmdline, false)?;
    }
    Ok(())
}

fn attach_unixsock_vsock_device(
    device_manager: &mut DeviceManager,
    vm: &Arc<Vm>,
    cmdline: &mut LoaderKernelCmdline,
    unix_vsock: &Arc<Mutex<Vsock<VsockUnixBackend>>>,
    event_manager: &mut EventManager,
) -> Result<(), AttachDeviceError> {
    let id = String::from(unix_vsock.lock().expect("Poisoned lock").id());
    event_manager.add_subscriber(unix_vsock.clone());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    device_manager.attach_virtio_device(vm, id, unix_vsock.clone(), cmdline, false)
}

fn attach_balloon_device(
    device_manager: &mut DeviceManager,
    vm: &Arc<Vm>,
    cmdline: &mut LoaderKernelCmdline,
    balloon: &Arc<Mutex<Balloon>>,
    event_manager: &mut EventManager,
) -> Result<(), AttachDeviceError> {
    let id = String::from(balloon.lock().expect("Poisoned lock").id());
    event_manager.add_subscriber(balloon.clone());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    device_manager.attach_virtio_device(vm, id, balloon.clone(), cmdline, false)
}

/// Creates GuestMemory of `mem_size_mib` MiB in size.
pub fn create_guest_memory(
    mem_size_mib: usize,
    backing_memory_file: Option<Arc<File>>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, StartMicrovmError> {
    let mem_size = mem_size_mib << 20;
    let arch_mem_regions = crate::arch::arch_memory_regions(mem_size);

    let mmap_flags = if backing_memory_file.is_some() {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS
    };

    crate::vstate::memory::create(
        arch_mem_regions.into_iter(),
        mmap_flags,
        backing_memory_file
            .map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|arc| (*arc).try_clone().unwrap())),
        track_dirty_pages,
    )
    .map_err(StartMicrovmError::GuestMemory)
}

/// Creates GuestMemory of `mem_size_mib` MiB in size with UFFD support.
pub fn create_uffd_guest_memory(
    mem_size_mib: usize,
    uds_socket_path: &Path,
    track_dirty_pages: bool,
) -> std::result::Result<(Vec<GuestRegionMmap>, Uffd, Arc<File>), StartMicrovmError> {
    use StartMicrovmError::{CreateUffdBuilder, NoMemFdReceived, UdsConnection, UffdSend};

    let mut socket = UnixStream::connect(uds_socket_path).map_err(UdsConnection)?;

    let mut buf = [0u8; 8];
    let (_, memfd) = socket
        .recv_with_fd(&mut buf)
        .map_err(|e| UdsConnection(std::io::Error::from_raw_os_error(e.errno())))?;

    if memfd.is_none() {
        return Err(NoMemFdReceived);
    }

    let mem_size = mem_size_mib << 20;
    let arch_mem_regions = arch::arch_memory_regions(mem_size);
    let backing_memory_file = memfd.unwrap();

    let guest_memory_regions = crate::vstate::memory::create(
        arch_mem_regions.into_iter(),
        libc::MAP_SHARED,
        Some(backing_memory_file.try_clone().unwrap()),
        track_dirty_pages,
    )
    .map_err(StartMicrovmError::GuestMemory)?;

    let backing_memory_file = Arc::new(backing_memory_file);

    let uffd = UffdBuilder::new()
        .require_features(
            FeatureFlags::EVENT_REMOVE
                | FeatureFlags::EVENT_REMAP
                | FeatureFlags::EVENT_FORK
                | FeatureFlags::EVENT_UNMAP
                | FeatureFlags::MISSING_SHMEM
                | FeatureFlags::PAGEFAULT_FLAG_WP,
        )
        .user_mode_only(false)
        .non_blocking(true)
        .create()
        .map_err(CreateUffdBuilder)?;

    let mut backend_mappings = Vec::with_capacity(guest_memory_regions.len());
    let mut offset = 0;
    let page_size = 4096; // Standard 4K page size
    for mem_region in &guest_memory_regions {
        let host_base_addr = mem_region.as_ptr();
        let size = mem_region.size();

        #[allow(deprecated)]
        backend_mappings.push(GuestRegionUffdMapping {
            base_host_virt_addr: host_base_addr as u64,
            size,
            offset,
            page_size,
            page_size_kib: page_size, // Field name is wrong but kept for API compatibility
        });
        offset += size as u64;
    }

    // This is safe to unwrap() because we control the contents of the vector
    // (i.e GuestRegionUffdMapping entries).
    let backend_mappings = serde_json::to_string(&backend_mappings).unwrap();

    socket
        .send_with_fd(
            backend_mappings.as_bytes(),
            // In the happy case we can close the fd since the other process has it open and is
            // using it to serve us pages.
            //
            // The problem is that if other process crashes/exits, firecracker guest memory
            // will simply revert to anon-mem behavior which would lead to silent errors and
            // undefined behavior.
            //
            // To tackle this scenario, the page fault handler can notify Firecracker of any
            // crashes/exits. There is no need for Firecracker to explicitly send its process ID.
            // The external process can obtain Firecracker's PID by calling `getsockopt` with
            // `libc::SO_PEERCRED` option like so:
            //
            // let mut val = libc::ucred { pid: 0, gid: 0, uid: 0 };
            // let mut ucred_size: u32 = mem::size_of::<libc::ucred>() as u32;
            // libc::getsockopt(
            //      socket.as_raw_fd(),
            //      libc::SOL_SOCKET,
            //      libc::SO_PEERCRED,
            //      &mut val as *mut _ as *mut _,
            //      &mut ucred_size as *mut libc::socklen_t,
            // );
            //
            // Per this linux man page: https://man7.org/linux/man-pages/man7/unix.7.html,
            // `SO_PEERCRED` returns the credentials (PID, UID and GID) of the peer process
            // connected to this socket. The returned credentials are those that were in effect
            // at the time of the `connect` call.
            //
            // Moreover, Firecracker holds a copy of the UFFD fd as well, so that even if the
            // page fault handler process does not tear down Firecracker when necessary, the
            // uffd will still be alive but with no one to serve faults, leading to guest freeze.
            uffd.as_raw_fd(),
        )
        .map_err(UffdSend)?;

    // Wait for UFFD to be ready.
    // TODO: maybe add a timeout?
    let mut buf = [0; 2];
    socket.read_exact(&mut buf).map_err(UdsConnection)?;

    Ok((guest_memory_regions, uffd, backing_memory_file))
}

#[cfg(test)]
pub(crate) mod tests {

    use linux_loader::cmdline::Cmdline;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::device_manager::tests::default_device_manager;
    use crate::devices::virtio::block::CacheType;
    use crate::devices::virtio::generated::virtio_ids;
    use crate::devices::virtio::rng::device::ENTROPY_DEV_ID;
    use crate::devices::virtio::vsock::VSOCK_DEV_ID;
    use crate::mmds::data_store::{Mmds, MmdsVersion};
    use crate::mmds::ns::MmdsNetworkStack;
    use crate::utils::mib_to_bytes;
    use crate::vmm_config::balloon::{BALLOON_DEV_ID, BalloonBuilder, BalloonDeviceConfig};
    use crate::vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;
    use crate::vmm_config::drive::{BlockBuilder, BlockDeviceConfig};
    use crate::vmm_config::entropy::{EntropyDeviceBuilder, EntropyDeviceConfig};
    use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig};
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vmm_config::vsock::{VsockBuilder, VsockDeviceConfig};
    use crate::vstate::vm::tests::setup_vm_with_memory;

    #[derive(Debug)]
    pub(crate) struct CustomBlockConfig {
        drive_id: String,
        is_root_device: bool,
        partuuid: Option<String>,
        is_read_only: bool,
        cache_type: CacheType,
    }

    impl CustomBlockConfig {
        pub(crate) fn new(
            drive_id: String,
            is_root_device: bool,
            partuuid: Option<String>,
            is_read_only: bool,
            cache_type: CacheType,
        ) -> Self {
            CustomBlockConfig {
                drive_id,
                is_root_device,
                partuuid,
                is_read_only,
                cache_type,
            }
        }
    }

    fn cmdline_contains(cmdline: &Cmdline, slug: &str) -> bool {
        // The following unwraps can never fail; the only way any of these methods
        // would return an `Err` is if one of the following conditions is met:
        //    1. The command line is empty: We just added things to it, and if insertion of an
        //       argument goes wrong, then `Cmdline::insert` would have already returned `Err`.
        //    2. There's a spurious null character somewhere in the command line: The
        //       `Cmdline::insert` methods verify that this is not the case.
        //    3. The `CString` is not valid UTF8: It just got created from a `String`, which was
        //       valid UTF8.

        cmdline
            .as_cstring()
            .unwrap()
            .into_string()
            .unwrap()
            .contains(slug)
    }

    pub(crate) fn default_kernel_cmdline() -> Cmdline {
        linux_loader::cmdline::Cmdline::try_from(
            DEFAULT_KERNEL_CMDLINE,
            crate::arch::CMDLINE_MAX_SIZE,
        )
        .unwrap()
    }

    pub(crate) fn default_vmm() -> Vmm {
        let (kvm, mut vm) = setup_vm_with_memory(mib_to_bytes(128));

        let (_, vcpus_exit_evt) = vm.create_vcpus(1).unwrap();

        Vmm {
            events_observer: Some(std::io::stdin()),
            instance_info: InstanceInfo::default(),
            shutdown_exit_code: None,
            kvm,
            vm: Arc::new(vm),
            vcpus_handles: Vec::new(),
            vcpus_exit_evt,
            device_manager: default_device_manager(),
            memory_descriptor: None,
        }
    }

    pub(crate) fn insert_block_devices(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        custom_block_cfgs: Vec<CustomBlockConfig>,
    ) -> Vec<TempFile> {
        let mut block_dev_configs = BlockBuilder::new();
        let mut block_files = Vec::new();
        for custom_block_cfg in custom_block_cfgs {
            block_files.push(TempFile::new().unwrap());

            let block_device_config = BlockDeviceConfig {
                drive_id: String::from(&custom_block_cfg.drive_id),
                partuuid: custom_block_cfg.partuuid,
                is_root_device: custom_block_cfg.is_root_device,
                cache_type: custom_block_cfg.cache_type,

                is_read_only: Some(custom_block_cfg.is_read_only),
                path_on_host: Some(
                    block_files
                        .last()
                        .unwrap()
                        .as_path()
                        .to_str()
                        .unwrap()
                        .to_string(),
                ),
                rate_limiter: None,
                file_engine_type: None,

                socket: None,
            };

            block_dev_configs.insert(block_device_config).unwrap();
        }

        attach_block_devices(
            &mut vmm.device_manager,
            &vmm.vm,
            cmdline,
            block_dev_configs.devices.iter(),
            event_manager,
        )
        .unwrap();
        block_files
    }

    pub(crate) fn insert_net_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        net_config: NetworkInterfaceConfig,
    ) {
        let mut net_builder = NetBuilder::new();
        net_builder.build(net_config).unwrap();

        let res = attach_net_devices(
            &mut vmm.device_manager,
            &vmm.vm,
            cmdline,
            net_builder.iter(),
            event_manager,
        );
        res.unwrap();
    }

    pub(crate) fn insert_net_device_with_mmds(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        net_config: NetworkInterfaceConfig,
        mmds_version: MmdsVersion,
    ) {
        let mut net_builder = NetBuilder::new();
        net_builder.build(net_config).unwrap();
        let net = net_builder.iter().next().unwrap();
        let mut mmds = Mmds::default();
        mmds.set_version(mmds_version);
        net.lock().unwrap().configure_mmds_network_stack(
            MmdsNetworkStack::default_ipv4_addr(),
            Arc::new(Mutex::new(mmds)),
        );

        attach_net_devices(
            &mut vmm.device_manager,
            &vmm.vm,
            cmdline,
            net_builder.iter(),
            event_manager,
        )
        .unwrap();
    }

    pub(crate) fn insert_vsock_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        vsock_config: VsockDeviceConfig,
    ) {
        let vsock_dev_id = VSOCK_DEV_ID.to_owned();
        let vsock = VsockBuilder::create_unixsock_vsock(vsock_config).unwrap();
        let vsock = Arc::new(Mutex::new(vsock));

        attach_unixsock_vsock_device(
            &mut vmm.device_manager,
            &vmm.vm,
            cmdline,
            &vsock,
            event_manager,
        )
        .unwrap();

        assert!(
            vmm.device_manager
                .get_virtio_device(virtio_ids::VIRTIO_ID_VSOCK, &vsock_dev_id)
                .is_some()
        );
    }

    pub(crate) fn insert_entropy_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        entropy_config: EntropyDeviceConfig,
    ) {
        let mut builder = EntropyDeviceBuilder::new();
        let entropy = builder.build(entropy_config).unwrap();

        attach_entropy_device(
            &mut vmm.device_manager,
            &vmm.vm,
            cmdline,
            &entropy,
            event_manager,
        )
        .unwrap();

        assert!(
            vmm.device_manager
                .get_virtio_device(virtio_ids::VIRTIO_ID_RNG, ENTROPY_DEV_ID)
                .is_some()
        );
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn insert_vmgenid_device(vmm: &mut Vmm) {
        vmm.device_manager
            .attach_vmgenid_device(vmm.vm.guest_memory(), &vmm.vm)
            .unwrap();
        assert!(vmm.device_manager.acpi_devices.vmgenid.is_some());
    }

    pub(crate) fn insert_balloon_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        balloon_config: BalloonDeviceConfig,
    ) {
        let mut builder = BalloonBuilder::new();
        builder.set(balloon_config).unwrap();
        let balloon = builder.get().unwrap();

        attach_balloon_device(
            &mut vmm.device_manager,
            &vmm.vm,
            cmdline,
            balloon,
            event_manager,
        )
        .unwrap();

        assert!(
            vmm.device_manager
                .get_virtio_device(virtio_ids::VIRTIO_ID_BALLOON, BALLOON_DEV_ID)
                .is_some()
        );
    }

    #[test]
    fn test_attach_net_devices() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        };

        let mut cmdline = default_kernel_cmdline();
        insert_net_device(
            &mut vmm,
            &mut cmdline,
            &mut event_manager,
            network_interface.clone(),
        );

        // We can not attach it once more.
        let mut net_builder = NetBuilder::new();
        net_builder.build(network_interface).unwrap_err();
    }

    #[test]
    fn test_attach_block_devices() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");

        // Use case 1: root block device is not specified through PARTUUID.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                None,
                true,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=/dev/vda ro"));
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 2: root block device is specified through PARTUUID.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                Some("0eaa91a0-01".to_string()),
                false,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=PARTUUID=0eaa91a0-01 rw"));
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 3: root block device is not added at all.
        {
            let drive_id = String::from("non_root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                false,
                Some("0eaa91a0-01".to_string()),
                false,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(!cmdline_contains(&cmdline, "root=PARTUUID="));
            assert!(!cmdline_contains(&cmdline, "root=/dev/vda"));
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 4: rw root block device and other rw and ro drives.
        {
            let block_configs = vec![
                CustomBlockConfig::new(
                    String::from("root"),
                    true,
                    Some("0eaa91a0-01".to_string()),
                    false,
                    CacheType::Unsafe,
                ),
                CustomBlockConfig::new(
                    String::from("secondary"),
                    false,
                    None,
                    true,
                    CacheType::Unsafe,
                ),
                CustomBlockConfig::new(
                    String::from("third"),
                    false,
                    None,
                    false,
                    CacheType::Unsafe,
                ),
            ];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);

            assert!(cmdline_contains(&cmdline, "root=PARTUUID=0eaa91a0-01 rw"));
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, "root")
                    .is_some()
            );
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, "secondary")
                    .is_some()
            );
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, "third")
                    .is_some()
            );

            // Check if these three block devices are inserted in kernel_cmdline.
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            assert!(cmdline_contains(
                &cmdline,
                "virtio_mmio.device=4K@0xc0001000:5 virtio_mmio.device=4K@0xc0002000:6 \
                 virtio_mmio.device=4K@0xc0003000:7"
            ));
        }

        // Use case 5: root block device is rw.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                None,
                false,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=/dev/vda rw"));
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 6: root block device is ro, with PARTUUID.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                Some("0eaa91a0-01".to_string()),
                true,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=PARTUUID=0eaa91a0-01 ro"));
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 7: root block device is rw with flush enabled
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                None,
                false,
                CacheType::Writeback,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=/dev/vda rw"));
            assert!(
                vmm.device_manager
                    .get_virtio_device(virtio_ids::VIRTIO_ID_BLOCK, drive_id.as_str())
                    .is_some()
            );
        }
    }

    #[test]
    fn test_attach_boot_timer_device() {
        let mut vmm = default_vmm();
        let request_ts = TimestampUs::default();

        let res = vmm
            .device_manager
            .attach_boot_timer_device(&vmm.vm, request_ts);
        res.unwrap();
        assert!(vmm.device_manager.mmio_devices.boot_timer.is_some());
    }

    #[test]
    fn test_attach_balloon_device() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let balloon_config = BalloonDeviceConfig {
            amount_mib: 0,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
        };

        let mut cmdline = default_kernel_cmdline();
        insert_balloon_device(&mut vmm, &mut cmdline, &mut event_manager, balloon_config);
        // Check if the vsock device is described in kernel_cmdline.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        assert!(cmdline_contains(
            &cmdline,
            "virtio_mmio.device=4K@0xc0001000:5"
        ));
    }

    #[test]
    fn test_attach_entropy_device() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let entropy_config = EntropyDeviceConfig::default();

        let mut cmdline = default_kernel_cmdline();
        insert_entropy_device(&mut vmm, &mut cmdline, &mut event_manager, entropy_config);
        // Check if the vsock device is described in kernel_cmdline.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        assert!(cmdline_contains(
            &cmdline,
            "virtio_mmio.device=4K@0xc0001000:5"
        ));
    }

    #[test]
    fn test_attach_vsock_device() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);

        let mut cmdline = default_kernel_cmdline();
        insert_vsock_device(&mut vmm, &mut cmdline, &mut event_manager, vsock_config);
        // Check if the vsock device is described in kernel_cmdline.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        assert!(cmdline_contains(
            &cmdline,
            "virtio_mmio.device=4K@0xc0001000:5"
        ));
    }
}
