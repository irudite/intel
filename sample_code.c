#include <stdio.h>
#include <stdlib.h>
#include "cpa.h"
#include "cpa_cy_im.h"
#include "icp_sal_user.h"
#include "qae_mem.h"
#include "icp_sal_poll.h"

int main(void)
{
    CpaStatus status;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaInstanceHandle cyInst = NULL;
    CpaInstanceInfo2 instInfo = {0};
    CpaCyCapabilitiesInfo caps = {0};

    /* --------------------------------------------------------
     * Step 1: Start the Service Access Layer.
     *
     * "SSL" must match a section name in your QAT config file.
     * For QATlib in-tree, this is typically /etc/sysconfig/qat
     * or managed by qatmgr.
     * -------------------------------------------------------- */
    printf("Starting SAL...\n");
    status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status) {
        printf("FAIL: icp_sal_userStartMultiProcess returned %d\n", status);
        printf("Check: Is qat.service running? Do VFs exist? Is qatmgr version matched?\n");
        return 1;
    }
    printf("SAL started.\n");

    /* --------------------------------------------------------
     * Step 2: Query how many crypto instances are available.
     * -------------------------------------------------------- */
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status) {
        printf("FAIL: cpaCyGetNumInstances returned %d\n", status);
        icp_sal_userStop();
        return 1;
    }
    printf("Found %u crypto instance(s).\n", numInstances);

    if (numInstances == 0) {
        printf("No crypto instances. Check config: ServicesEnabled must include asym or cy.\n");
        icp_sal_userStop();
        return 1;
    }

    /* --------------------------------------------------------
     * Step 3: Get instance handles and grab the first one.
     * -------------------------------------------------------- */
    instances = malloc(numInstances * sizeof(CpaInstanceHandle));
    if (!instances) {
        printf("FAIL: malloc\n");
        icp_sal_userStop();
        return 1;
    }

    status = cpaCyGetInstances(numInstances, instances);
    if (CPA_STATUS_SUCCESS != status) {
        printf("FAIL: cpaCyGetInstances returned %d\n", status);
        free(instances);
        icp_sal_userStop();
        return 1;
    }

    cyInst = instances[0];
    free(instances);

    /* --------------------------------------------------------
     * Step 4: Set address translation.
     *
     * QAT uses DMA. It needs physical addresses.
     * qaeVirtToPhysNUMA converts USDM virtual addresses
     * to physical addresses the hardware uses.
     * -------------------------------------------------------- */
    status = cpaCySetAddressTranslation(cyInst, qaeVirtToPhysNUMA);
    if (CPA_STATUS_SUCCESS != status) {
        printf("FAIL: cpaCySetAddressTranslation returned %d\n", status);
        icp_sal_userStop();
        return 1;
    }

    /* --------------------------------------------------------
     * Step 5: Start the instance.
     *
     * Activates the hardware queue pair. No operations work
     * until this is called.
     * -------------------------------------------------------- */
    status = cpaCyStartInstance(cyInst);
    if (CPA_STATUS_SUCCESS != status) {
        printf("FAIL: cpaCyStartInstance returned %d\n", status);
        icp_sal_userStop();
        return 1;
    }
    printf("Instance started.\n");

    /* --------------------------------------------------------
     * Step 6: Print instance info.
     * -------------------------------------------------------- */
    cpaCyInstanceGetInfo2(cyInst, &instInfo);
    printf("\n=== Instance Info ===\n");
    printf("  Name:       %s\n", instInfo.instName);
    printf("  Part:       %s\n", instInfo.partName);
    printf("  Node:       %d\n", instInfo.nodeAffinity);
    printf("  Is Polled:  %s\n", instInfo.isPolled ? "yes" : "no");
    printf("  State:      %s\n",
           instInfo.operState == CPA_OPER_STATE_UP ? "UP" : "DOWN");

    /* --------------------------------------------------------
     * Step 7: Query crypto capabilities.
     *
     * This tells you exactly which asymmetric operations
     * the hardware supports on this instance.
     * -------------------------------------------------------- */
    status = cpaCyQueryCapabilities(cyInst, &caps);
    if (CPA_STATUS_SUCCESS != status) {
        printf("FAIL: cpaCyQueryCapabilities returned %d\n", status);
        cpaCyStopInstance(cyInst);
        icp_sal_userStop();
        return 1;
    }

    printf("\n=== Asymmetric Crypto Capabilities ===\n");
    printf("  Diffie-Hellman:    %s\n", caps.dhSupported          ? "YES" : "no");
    printf("  DSA:               %s\n", caps.dsaSupported          ? "YES" : "no");
    printf("  RSA:               %s\n", caps.rsaSupported          ? "YES" : "no");
    printf("  EC Diffie-Hellman: %s\n", caps.ecdhSupported         ? "YES" : "no");
    printf("  ECDSA:             %s\n", caps.ecdsaSupported        ? "YES" : "no");
    printf("  EC SM2:            %s\n", caps.ecSm2Supported        ? "YES" : "no");
    printf("  Large Number:      %s\n", caps.lnSupported           ? "YES" : "no");
    printf("  Prime Test:        %s\n", caps.primeSupported        ? "YES" : "no");
    printf("  EC EdMontgomery:   %s\n", caps.ecEdMontSupported     ? "YES" : "no");

    printf("\n=== Symmetric Crypto Capabilities ===\n");
    printf("  Symmetric:         %s\n", caps.symSupported              ? "YES" : "no");
    printf("  Ext Alg Chain:     %s\n", caps.extAlgchainSupported      ? "YES" : "no");

    printf("\nHello QAT crypto. Your hardware is alive.\n");

    /* --------------------------------------------------------
     * Step 8: Cleanup.
     * -------------------------------------------------------- */
    cpaCyStopInstance(cyInst);
    icp_sal_userStop();

    printf("Done.\n");
    return 0;
}
