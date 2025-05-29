/*
 * QEMU Arm RME support
 *
 * Copyright Linaro 2024
 */

#include "qemu/osdep.h"

#include "exec/confidential-guest-support.h"
#include "hw/boards.h"
#include "hw/core/cpu.h"
#include "hw/loader.h"
#include "hw/tpm/tpm_log.h"
#include "kvm_arm.h"
#include "migration/blocker.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qom/object_interfaces.h"
#include "sysemu/kvm.h"
#include "sysemu/runstate.h"

#define TYPE_RME_GUEST "rme-guest"
OBJECT_DECLARE_SIMPLE_TYPE(RmeGuest, RME_GUEST)

#define RME_PAGE_SIZE qemu_real_host_page_size()

#define RME_MAX_CFG         2

#define RME_MEASUREMENT_LOG_SIZE    (64 * KiB)

struct RmeGuest {
    ConfidentialGuestSupport parent_obj;
    Notifier rom_load_notifier;
    GSList *ram_regions;

    uint8_t *personalization_value;
    RmeGuestMeasurementAlgorithm measurement_algo;
    bool use_measurement_log;

    size_t num_cpus;
    uint8_t ipa_bits;
    hwaddr ram_base;
    size_t ram_size;

    TpmLog *log;
    GHashTable *images;
};

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(RmeGuest, rme_guest, RME_GUEST,
                                          CONFIDENTIAL_GUEST_SUPPORT,
                                          { TYPE_USER_CREATABLE }, { })

typedef struct RmeLogFiletype {
    uint32_t event_type;
    /* Description copied into the log event */
    const char *desc;
} RmeLogFiletype;

typedef struct {
    hwaddr base;
    hwaddr size;
    uint8_t *data;
    RmeLogFiletype *filetype;
} RmeRamRegion;

typedef struct {
    char        signature[16];
    char        name[32];
    char        version[40];
    uint64_t    ram_size;
    uint32_t    num_cpus;
    uint64_t    flags;
} EventLogVmmVersion;

typedef struct {
    uint32_t    id;
    uint32_t    data_size;
    uint8_t     data[];
} EventLogTagged;

#define EVENT_LOG_TAG_REALM_CREATE  1
#define EVENT_LOG_TAG_INIT_RIPAS    2
#define EVENT_LOG_TAG_REC_CREATE    3

#define REALM_PARAMS_FLAG_SVE       (1 << 1)
#define REALM_PARAMS_FLAG_PMU       (1 << 2)

#define REC_CREATE_FLAG_RUNNABLE    (1 << 0)

static RmeGuest *rme_guest;

static int rme_init_measurement_log(MachineState *ms)
{
    Object *log;
    gpointer filename;
    TpmLogDigestAlgo algo;
    RmeLogFiletype *filetype;

    if (!rme_guest->use_measurement_log) {
        return 0;
    }

    switch (rme_guest->measurement_algo) {
    case RME_GUEST_MEASUREMENT_ALGORITHM_SHA256:
        algo = TPM_LOG_DIGEST_ALGO_SHA256;
        break;
    case RME_GUEST_MEASUREMENT_ALGORITHM_SHA512:
        algo = TPM_LOG_DIGEST_ALGO_SHA512;
        break;
    default:
        g_assert_not_reached();
    }

    log = object_new_with_props(TYPE_TPM_LOG, OBJECT(rme_guest),
                                "log", &error_fatal,
                                "digest-algo", TpmLogDigestAlgo_str(algo),
                                NULL);

    tpm_log_create(TPM_LOG(log), RME_MEASUREMENT_LOG_SIZE, &error_fatal);
    rme_guest->log = TPM_LOG(log);

    /*
     * Write down the image names we're expecting to encounter when handling the
     * ROM load notifications, so we can record the type of image being loaded
     * to help the verifier.
     */
    rme_guest->images = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                              g_free);

    filename = g_strdup(ms->kernel_filename);
    if (filename) {
        filetype = g_new0(RmeLogFiletype, 1);
        filetype->event_type = TCG_EV_POST_CODE2;
        filetype->desc = "KERNEL";
        g_hash_table_insert(rme_guest->images, filename, (gpointer)filetype);
    }

    filename = g_strdup(ms->initrd_filename);
    if (filename) {
        filetype = g_new0(RmeLogFiletype, 1);
        filetype->event_type = TCG_EV_POST_CODE2;
        filetype->desc = "INITRD";
        g_hash_table_insert(rme_guest->images, filename, (gpointer)filetype);
    }

    filename = g_strdup(ms->firmware);
    if (filename) {
        filetype = g_new0(RmeLogFiletype, 1);
        filetype->event_type = TCG_EV_EFI_PLATFORM_FIRMWARE_BLOB2;
        filetype->desc = "FIRMWARE";
        g_hash_table_insert(rme_guest->images, filename, filetype);
    }

    filename = g_strdup(ms->dtb);
    if (!filename) {
        filename = g_strdup("dtb");
    }
    filetype = g_new0(RmeLogFiletype, 1);
    filetype->event_type = TCG_EV_POST_CODE2;
    filetype->desc = "DTB";
    g_hash_table_insert(rme_guest->images, filename, filetype);

    return 0;
}

static int rme_log_event_tag(uint32_t id, uint8_t *data, size_t size,
                             Error **errp)
{
    int ret;
    EventLogTagged event = {
        .id = id,
        .data_size = size,
    };
    GByteArray *bytes = g_byte_array_new();

    if (!rme_guest->log) {
        return 0;
    }

    g_byte_array_append(bytes, (uint8_t *)&event, sizeof(event));
    g_byte_array_append(bytes, data, size);
    ret = tpm_log_add_event(rme_guest->log, TCG_EV_EVENT_TAG, bytes->data,
                             bytes->len, NULL, 0, errp);
    g_byte_array_free(bytes, true);
    return ret;
}

/* Log VM type and Realm Descriptor create */
static int rme_log_realm_create(Error **errp)
{
    int ret;
    ARMCPU *cpu;
    EventLogVmmVersion vmm_version = {
        .signature = "VM VERSION",
        .name = "QEMU",
        .version = "9.1", /* TODO: dynamic */
        .ram_size = cpu_to_le64(rme_guest->ram_size),
        .num_cpus = cpu_to_le32(rme_guest->num_cpus),
        .flags = 0,
    };
    struct {
        uint64_t    flags;
        uint8_t     s2sz;
        uint8_t     sve_vl;
        uint8_t     num_bps;
        uint8_t     num_wps;
        uint8_t     pmu_num_ctrs;
        uint8_t     hash_algo;
    } params = {
        .s2sz = rme_guest->ipa_bits,
    };

    if (!rme_guest->log) {
        return 0;
    }

    ret = tpm_log_add_event(rme_guest->log, TCG_EV_NO_ACTION,
                            (uint8_t *)&vmm_version, sizeof(vmm_version),
                            NULL, 0, errp);
    if (ret) {
        return ret;
    }

    /* With KVM all CPUs have the same capability */
    cpu = ARM_CPU(first_cpu);
    if (cpu->has_pmu) {
        params.flags |= REALM_PARAMS_FLAG_PMU;
        params.pmu_num_ctrs = FIELD_EX64(cpu->isar.reset_pmcr_el0, PMCR, N);
    }

    if (cpu->sve_max_vq) {
        params.flags |= REALM_PARAMS_FLAG_SVE;
        params.sve_vl = cpu->sve_max_vq - 1;
    }
    params.num_bps = FIELD_EX64(cpu->isar.id_aa64dfr0, ID_AA64DFR0, BRPS);
    params.num_wps = FIELD_EX64(cpu->isar.id_aa64dfr0, ID_AA64DFR0, WRPS);

    switch (rme_guest->measurement_algo) {
    case RME_GUEST_MEASUREMENT_ALGORITHM_SHA256:
        params.hash_algo = KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256;
        break;
    case RME_GUEST_MEASUREMENT_ALGORITHM_SHA512:
        params.hash_algo = KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512;
        break;
    default:
        g_assert_not_reached();
    }

    return rme_log_event_tag(EVENT_LOG_TAG_REALM_CREATE, (uint8_t *)&params,
                             sizeof(params), errp);
}

/* unmeasured images are logged with @data == NULL */
static int rme_log_image(RmeLogFiletype *filetype, uint8_t *data, hwaddr base,
                          size_t size, Error **errp)
{
    int ret;
    size_t desc_size;
    GByteArray *event = g_byte_array_new();
    struct UefiPlatformFirmwareBlob2Head head = {0};
    struct UefiPlatformFirmwareBlob2Tail tail = {0};

    if (!rme_guest->log) {
        return 0;
    }

    if (!filetype) {
        error_setg(errp, "cannot log image without a filetype");
        return -1;
    }

    /* EV_POST_CODE2 strings are not NUL-terminated */
    desc_size = strlen(filetype->desc);
    head.blob_description_size = desc_size;
    tail.blob_base = cpu_to_le64(base);
    tail.blob_size = cpu_to_le64(size);

    g_byte_array_append(event, (guint8 *)&head, sizeof(head));
    g_byte_array_append(event, (guint8 *)filetype->desc, desc_size);
    g_byte_array_append(event, (guint8 *)&tail, sizeof(tail));

    ret = tpm_log_add_event(rme_guest->log, filetype->event_type, event->data,
                            event->len, data, size, errp);
    g_byte_array_free(event, true);
    return ret;
}

static int rme_log_ripas(hwaddr base, size_t size, Error **errp)
{
    struct {
        uint64_t base;
        uint64_t size;
    } init_ripas = {
        .base = cpu_to_le64(base),
        .size = cpu_to_le64(size),
    };

    return rme_log_event_tag(EVENT_LOG_TAG_INIT_RIPAS, (uint8_t *)&init_ripas,
                             sizeof(init_ripas), errp);
}

static int rme_log_rec(uint64_t flags, uint64_t pc, uint64_t gprs[8], Error **errp)
{
    struct {
        uint64_t flags;
        uint64_t pc;
        uint64_t gprs[8];
    } rec_create = {
        .flags = cpu_to_le64(flags),
        .pc = cpu_to_le64(pc),
        .gprs[0] = cpu_to_le64(gprs[0]),
        .gprs[1] = cpu_to_le64(gprs[1]),
        .gprs[2] = cpu_to_le64(gprs[2]),
        .gprs[3] = cpu_to_le64(gprs[3]),
        .gprs[4] = cpu_to_le64(gprs[4]),
        .gprs[5] = cpu_to_le64(gprs[5]),
        .gprs[6] = cpu_to_le64(gprs[6]),
        .gprs[7] = cpu_to_le64(gprs[7]),
    };

    return rme_log_event_tag(EVENT_LOG_TAG_REC_CREATE, (uint8_t *)&rec_create,
                             sizeof(rec_create), errp);
}

static int rme_populate_range(hwaddr base, size_t size, bool measure,
                              Error **errp);

static int rme_close_measurement_log(Error **errp)
{
    int ret;
    hwaddr base;
    size_t size;
    RmeLogFiletype filetype = {
        .event_type = TCG_EV_POST_CODE2,
        .desc = "LOG",
    };

    if (!rme_guest->log) {
        return 0;
    }

    base = object_property_get_uint(OBJECT(rme_guest->log), "load-addr", errp);
    if (*errp) {
        return -1;
    }

    size = object_property_get_uint(OBJECT(rme_guest->log), "max-size", errp);
    if (*errp) {
        return -1;
    }

    /* Log the log itself */
    ret = rme_log_image(&filetype, NULL, base, size, errp);
    if (ret) {
        return ret;
    }

    ret = tpm_log_write_and_close(rme_guest->log, errp);
    if (ret) {
        return ret;
    }

    ret = rme_populate_range(base, size, /* measure */ false, errp);
    if (ret) {
        return ret;
    }

    g_hash_table_destroy(rme_guest->images);

    /* The log is now in the guest. Free this object */
    object_unparent(OBJECT(rme_guest->log));
    rme_guest->log = NULL;
    return 0;
}

static int rme_configure_one(RmeGuest *guest, uint32_t cfg, Error **errp)
{
    int ret;
    const char *cfg_str;
    struct kvm_cap_arm_rme_config_item args = {
        .cfg = cfg,
    };

    switch (cfg) {
    case KVM_CAP_ARM_RME_CFG_RPV:
        if (!guest->personalization_value) {
            return 0;
        }
        memcpy(args.rpv, guest->personalization_value, KVM_CAP_ARM_RME_RPV_SIZE);
        cfg_str = "personalization value";
        break;
    case KVM_CAP_ARM_RME_CFG_HASH_ALGO:
        switch (guest->measurement_algo) {
        case RME_GUEST_MEASUREMENT_ALGORITHM_SHA256:
            args.hash_algo = KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256;
            break;
        case RME_GUEST_MEASUREMENT_ALGORITHM_SHA512:
            args.hash_algo = KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512;
            break;
        default:
            g_assert_not_reached();
        }
        cfg_str = "hash algorithm";
        break;
    default:
        g_assert_not_reached();
    }

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_CONFIG_REALM, (intptr_t)&args);
    if (ret) {
        error_setg_errno(errp, -ret, "failed to configure %s", cfg_str);
    }
    return ret;
}

static int rme_configure(Error **errp)
{
    int ret;
    int cfg;

    for (cfg = 0; cfg < RME_MAX_CFG; cfg++) {
        ret = rme_configure_one(rme_guest, cfg, errp);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

static int rme_init_ram(hwaddr base, size_t size, Error **errp)
{
    int ret;
    uint64_t start = QEMU_ALIGN_DOWN(base, RME_PAGE_SIZE);
    uint64_t end = QEMU_ALIGN_UP(base + size, RME_PAGE_SIZE);
    struct kvm_cap_arm_rme_init_ipa_args init_args = {
        .init_ipa_base = start,
        .init_ipa_size = end - start,
    };

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_INIT_IPA_REALM,
                            (intptr_t)&init_args);
    if (ret) {
        error_setg_errno(errp, -ret,
                         "failed to init RAM [0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx")",
                         start, end);
        return ret;
    }

    return rme_log_ripas(base, size, errp);
}

static int rme_populate_range(hwaddr base, size_t size, bool measure,
                              Error **errp)
{
    int ret;
    uint64_t start = QEMU_ALIGN_DOWN(base, RME_PAGE_SIZE);
    uint64_t end = QEMU_ALIGN_UP(base + size, RME_PAGE_SIZE);
    printf("start %lx end %lx\n");
    struct kvm_cap_arm_rme_populate_realm_args populate_args = {
        .populate_ipa_base = start,
        .populate_ipa_size = end - start,
        .flags = measure ? KVM_ARM_RME_POPULATE_FLAGS_MEASURE : 0,
    };

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_POPULATE_REALM,
                            (intptr_t)&populate_args);
    if (ret) {
        error_setg_errno(errp, -ret,
                   "failed to populate realm [0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx")",
                   start, end);
    }
    return ret;
}

static void rme_populate_ram_region(gpointer data, gpointer err)
{
    Error **errp = err;
    const RmeRamRegion *region = data;

    if (*errp) {
        return;
    }

    rme_populate_range(region->base, region->size, /* measure */ true, errp);
    if (*errp) {
        return;
    }

    rme_log_image(region->filetype, region->data, region->base, region->size,
                  errp);
}

static int rme_init_cpus(Error **errp)
{
    int ret;
    CPUState *cs;
    bool logged_primary_cpu = false;

    /*
     * Now that do_cpu_reset() initialized the boot PC and
     * kvm_cpu_synchronize_post_reset() registered it, we can finalize the REC.
     */
    CPU_FOREACH(cs) {
        ARMCPU *cpu = ARM_CPU(cs);

        ret = kvm_arm_vcpu_finalize(cpu, KVM_ARM_VCPU_REC);
        if (ret) {
            error_setg_errno(errp, -ret, "failed to finalize vCPU");
            return ret;
        }

        if (!logged_primary_cpu) {
            ret = rme_log_rec(REC_CREATE_FLAG_RUNNABLE, cpu->env.pc,
                              cpu->env.xregs, errp);
            if (ret) {
                return ret;
            }

            logged_primary_cpu = true;
        }
    }
    return 0;
}

static int rme_create_realm(Error **errp)
{
    int ret;

    if (rme_configure(errp)) {
        return -1;
    }

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_CREATE_RD);
    if (ret) {
        error_setg_errno(errp, -ret, "failed to create Realm Descriptor");
        return -1;
    }

    if (rme_log_realm_create(errp)) {
        return -1;
    }

    if (rme_init_ram(rme_guest->ram_base, rme_guest->ram_size, errp)) {
        return -1;
    }

    g_slist_foreach(rme_guest->ram_regions, rme_populate_ram_region, errp);
    g_slist_free_full(g_steal_pointer(&rme_guest->ram_regions), g_free);
    if (*errp) {
        return -1;
    }

    if (rme_init_cpus(errp)) {
        return -1;
    }

    if (rme_close_measurement_log(errp)) {
        return -1;
    }

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_ARM_RME, 0,
                            KVM_CAP_ARM_RME_ACTIVATE_REALM);
    if (ret) {
        error_setg_errno(errp, -ret, "failed to activate realm");
        return -1;
    }

    kvm_mark_guest_state_protected();
    return 0;
}

static void rme_vm_state_change(void *opaque, bool running, RunState state)
{
    Error *err = NULL;

    if (!running) {
        return;
    }

    if (rme_create_realm(&err)) {
        error_propagate_prepend(&error_fatal, err, "RME: ");
    }
}

static char *rme_get_rpv(Object *obj, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);
    GString *s;
    int i;

    if (!guest->personalization_value) {
        return NULL;
    }

    s = g_string_sized_new(KVM_CAP_ARM_RME_RPV_SIZE * 2 + 1);

    for (i = 0; i < KVM_CAP_ARM_RME_RPV_SIZE; i++) {
        g_string_append_printf(s, "%02x", guest->personalization_value[i]);
    }

    return g_string_free(s, /* free_segment */ false);
}

static void rme_set_rpv(Object *obj, const char *value, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);
    size_t len = strlen(value);
    uint8_t *out;
    int i = 1;
    int ret;

    g_free(guest->personalization_value);
    guest->personalization_value = out = g_malloc0(KVM_CAP_ARM_RME_RPV_SIZE);

    /* Two chars per byte */
    if (len > KVM_CAP_ARM_RME_RPV_SIZE * 2) {
        error_setg(errp, "Realm Personalization Value is too large");
        return;
    }

    /* First byte may have a single char */
    if (len % 2) {
        ret = sscanf(value, "%1hhx", out++);
    } else {
        ret = sscanf(value, "%2hhx", out++);
        i++;
    }
    if (ret != 1) {
        error_setg(errp, "Invalid Realm Personalization Value");
        return;
    }

    for (; i < len; i += 2) {
        ret = sscanf(value + i, "%2hhx", out++);
        if (ret != 1) {
            error_setg(errp, "Invalid Realm Personalization Value");
            return;
        }
    }
}

static int rme_get_measurement_algo(Object *obj, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);

    return guest->measurement_algo;
}

static void rme_set_measurement_algo(Object *obj, int algo, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);

    guest->measurement_algo = algo;
}

static bool rme_get_measurement_log(Object *obj, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);

    return guest->use_measurement_log;
}

static void rme_set_measurement_log(Object *obj, bool value, Error **errp)
{
    RmeGuest *guest = RME_GUEST(obj);

    guest->use_measurement_log = value;
}

static void rme_guest_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add_str(oc, "personalization-value", rme_get_rpv,
                                  rme_set_rpv);
    object_class_property_set_description(oc, "personalization-value",
            "Realm personalization value (512-bit hexadecimal number)");

    object_class_property_add_enum(oc, "measurement-algorithm",
                                   "RmeGuestMeasurementAlgorithm",
                                   &RmeGuestMeasurementAlgorithm_lookup,
                                   rme_get_measurement_algo,
                                   rme_set_measurement_algo);
    object_class_property_set_description(oc, "measurement-algorithm",
            "Realm measurement algorithm ('sha256', 'sha512')");

    object_class_property_add_bool(oc, "measurement-log",
                                   rme_get_measurement_log,
                                   rme_set_measurement_log);
    object_class_property_set_description(oc, "measurement-log",
            "Enable/disable Realm measurement log");
}

static void rme_guest_init(Object *obj)
{
    if (rme_guest) {
        error_report("a single instance of RmeGuest is supported");
        exit(1);
    }
    rme_guest = RME_GUEST(obj);
    rme_guest->measurement_algo = RME_GUEST_MEASUREMENT_ALGORITHM_SHA512;
}

static void rme_guest_finalize(Object *obj)
{
}

static gint rme_compare_ram_regions(gconstpointer a, gconstpointer b)
{
        const RmeRamRegion *ra = a;
        const RmeRamRegion *rb = b;

        g_assert(ra->base != rb->base);
        return ra->base < rb->base ? -1 : 1;
}

static void rme_rom_load_notify(Notifier *notifier, void *data)
{
    RmeRamRegion *region;
    RomLoaderNotify *rom = data;

    if (rom->addr == -1) {
        /*
         * These blobs (ACPI tables) are not loaded into guest RAM at reset.
         * Instead the firmware will load them via fw_cfg and measure them
         * itself.
         */
        return;
    }

    region = g_new0(RmeRamRegion, 1);
    region->base = rom->addr;
    region->size = rom->len;
    /*
     * TODO: double-check lifetime. Is data is still available when we measure
     * it, while writing the log. Should be fine since data is kept for the next
     * reset.
     */
    region->data = rom->data;

    /*
     * rme_guest->images is destroyed after ram_regions, so we can store
     * filetype even if we don't own the struct.
     */
    if (rme_guest->images) {
        region->filetype = g_hash_table_lookup(rme_guest->images, rom->name);
    }

    /*
     * The Realm Initial Measurement (RIM) depends on the order in which we
     * initialize and populate the RAM regions. To help a verifier
     * independently calculate the RIM, sort regions by GPA.
     */
    rme_guest->ram_regions = g_slist_insert_sorted(rme_guest->ram_regions,
                                                   region,
                                                   rme_compare_ram_regions);
}

int kvm_arm_rme_init(MachineState *ms)
{
    static Error *rme_mig_blocker;
    ConfidentialGuestSupport *cgs = ms->cgs;

    if (!rme_guest) {
        return 0;
    }

    if (!cgs) {
        error_report("missing -machine confidential-guest-support parameter");
        return -EINVAL;
    }

    if (!kvm_check_extension(kvm_state, KVM_CAP_ARM_RME)) {
        return -ENODEV;
    }

    if (rme_init_measurement_log(ms)) {
        return -ENODEV;
    }

    rme_guest->ram_size = ms->ram_size;
    rme_guest->num_cpus = ms->smp.max_cpus;

    error_setg(&rme_mig_blocker, "RME: migration is not implemented");
    migrate_add_blocker(&rme_mig_blocker, &error_fatal);

    /*
     * The realm activation is done last, when the VM starts, after all images
     * have been loaded and all vcpus finalized.
     */
    qemu_add_vm_change_state_handler(rme_vm_state_change, NULL);

    rme_guest->rom_load_notifier.notify = rme_rom_load_notify;
    rom_add_load_notifier(&rme_guest->rom_load_notifier);

    cgs->require_guest_memfd = true;
    cgs->ready = true;
    return 0;
}

void kvm_arm_rme_init_guest_ram(hwaddr base, size_t size)
{
    if (rme_guest) {
        rme_guest->ram_base = base;
        rme_guest->ram_size = size;
    }
}

int kvm_arm_rme_vcpu_init(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);

    if (rme_guest) {
        cpu->kvm_rme = true;
    }
    return 0;
}

int kvm_arm_rme_vm_type(MachineState *ms)
{
    if (rme_guest) {
        return KVM_VM_TYPE_ARM_REALM;
    }
    return 0;
}

void kvm_arm_rme_set_ipa_size(uint8_t ipa_bits)
{
    if (rme_guest) {
        /* We request one more bit to KVM as the NS flag */
        rme_guest->ipa_bits = ipa_bits + 1;
    }
}

Object *kvm_arm_rme_get_measurement_log(void)
{
    if (rme_guest) {
        return OBJECT(rme_guest->log);
    }
    return NULL;
}
