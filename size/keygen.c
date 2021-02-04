/* This is example app uses the IBM TSS2 Stack to
 * perform three of the most common TPM operations:
 * Create Primary Key under the owner Hierarchy,
 * Create Signing Key under a Primary Key,
 * Load the Signing Key for use. And unloading all.
 *
 * <dimi@wolfssl.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>
#include "../utils/objecttemplates.h"
#include "../utils/cryptoutils.h"

static const char gStorageKeyAuth[] = "ThisIsMyStorageKeyAuth\0";
static const char gKeyAuth[] =        "ThisIsMyKeyAuth\0";
static const char gUsageAuth[] =      "ThisIsASecretUsageAuth\0";

void usage(void)
{
    printf("Expected usage:\n");
    printf("./size/keygen -ecc/-rsa [-aes]\n");
    printf("* -ecc: Use ECC for keys\n");
    printf("* -rsa: Use RSA for keys\n");
    printf("* -aes: Use Parameter Encryption (AES CFB)\n");
}

int main(int argc, char *argv[])
{
    TPM_RC rc = 0;
    TSS_CONTEXT *tssContext = NULL;
    TPMI_RH_HIERARCHY primaryHandle = TPM_RH_OWNER;
    TPMI_DH_OBJECT parentHandle;
    TPMT_PUBLIC publicArea;
    TPMA_OBJECT addObjectAttributes;
    TPMA_OBJECT deleteObjectAttributes;
    /* Command buffers */
    CreatePrimary_In inPrimary;
    CreatePrimary_Out outPrimary;
    Create_In inCreate;
    Create_Out outCreate;
    Load_In inLoad;
    Load_Out outLoad;
    FlushContext_In inFlush;
    /* Default key type is RSA 2048 */
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA;
    TPMI_ALG_HASH hashAlg = TPM_ALG_SHA256;
    TPMI_ALG_HASH nalg = TPM_ALG_SHA256;
    TPMI_RSA_KEY_BITS keyBits = 2048;
    TPMI_ECC_CURVE eccCurveID = TPM_ECC_NONE;
    TPMI_SH_AUTH_SESSION sessionHandle0, sessionHandle1, sessionHandle2;
    unsigned int sessionAttributes0, sessionAttributes1, sessionAttributes2;
    int keyType; /* Key type for IBM TSS */
    int paramEncAlg; /* User option */


    if (argc >= 2) {
        if (strncmp(argv[1], "-?", 2) == 0 ||
            strncmp(argv[1], "-h", 2) == 0 ||
            strncmp(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
    }

    while (argc > 1) {
        if (strncmp(argv[argc-1], "-ecc", 4) == 0) {
            alg = TPM_ALG_ECC;
            eccCurveID = TPM_ECC_NIST_P256;
        }
        else if (strncmp(argv[argc-1], "-rsa", 4) == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (strncmp(argv[argc-1], "-aes", 4) == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else {
            printf("Wrong argument %d\n", argc-1);
            usage();
            return 0;
        }
        argc--;
    }

    if (alg == TPM_ALG_NULL) {
        usage();
        return 0;
    }

    sessionHandle0 = TPM_RS_PW;
    sessionHandle1 = sessionHandle2 = TPM_RH_NULL;
    sessionAttributes0 = sessionAttributes1 = sessionAttributes2 = 0;

    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
    addObjectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    deleteObjectAttributes.val = 0;

#ifdef DEBUG
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
#endif

    /* Prepare Primary (Storage) Key under Owner Hierarchy */
    keyType = TYPE_ST;
    inPrimary.primaryHandle = primaryHandle;
    inPrimary.inSensitive.sensitive.data.t.size = 0;
    /* Asym Key properties */
    rc = asymPublicTemplate(&inPrimary.inPublic.publicArea,
                addObjectAttributes, deleteObjectAttributes,
                keyType, alg, keyBits, eccCurveID, nalg, hashAlg,
                NULL);
    if(rc != 0) {
        printf("Getting Public Template for Storage Key failed\n");
        goto exit;
    }
    /* Optional properties */
    inPrimary.outsideInfo.t.size = 0;
    inPrimary.creationPCR.count = 0;
    /* Set what password to have the Storage Key */
    rc = TSS_TPM2B_StringCopy(&inPrimary.inSensitive.sensitive.userAuth.b,
                    gStorageKeyAuth, sizeof(inPrimary.inSensitive.sensitive.userAuth.t.buffer));

    /* Create IBM TSS Context for work */
    rc = TSS_Create(&tssContext);
    if (rc != 0) {
        printf("TSS_Create failed\n");
        goto exit;
    }
    printf("TSS_Create executed\n");

    /* Create Primary Key */
    rc = TSS_Execute(tssContext,
                (RESPONSE_PARAMETERS *)&outPrimary,
                (COMMAND_PARAMETERS *)&inPrimary,
                NULL, TPM_CC_CreatePrimary,
                sessionHandle0, NULL, sessionAttributes0,
                sessionHandle1, NULL, sessionAttributes1,
                sessionHandle2, NULL, sessionAttributes2,
                TPM_RH_NULL, NULL, 0);
    if (rc != 0) {
        printf("TSS_Execute of TPM_CC_CreatePrimary failed\n");
        goto exit;
    }
    printf("TSS_Execute of TPM_CC_CreatePrimary is a success\n");

    /* Prepare Signing Key */
    keyType = TYPE_SI;
    inCreate.parentHandle = outPrimary.objectHandle;

    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    addObjectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    addObjectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    deleteObjectAttributes.val = 0;
    /* Asym Key Properties for Signing Key */
    rc = asymPublicTemplate(&inCreate.inPublic.publicArea,
            addObjectAttributes, deleteObjectAttributes,
            keyType, alg, keyBits, eccCurveID, nalg, hashAlg,
            NULL);
    if(rc != 0) {
        printf("Getting Public Template for Signing Key failed\n");
        goto exit_flush_primary;
    }
    /* Optional properties */
    inCreate.outsideInfo.t.size = 0;
    inCreate.creationPCR.count = 0;
    /* Set what password to have the Signing Key */
    rc = TSS_TPM2B_StringCopy(&inCreate.inSensitive.sensitive.userAuth.b,
                    gKeyAuth, sizeof(inCreate.inSensitive.sensitive.userAuth.t.buffer));

    /* Create Signing Key under the Storage Key */
    rc = TSS_Execute(tssContext,
                (RESPONSE_PARAMETERS *)&outCreate,
                (COMMAND_PARAMETERS *)&inCreate,
                NULL, TPM_CC_Create,
                sessionHandle0, gStorageKeyAuth, sessionAttributes0,
                sessionHandle1, NULL, sessionAttributes1,
                sessionHandle2, NULL, sessionAttributes2,
                TPM_RH_NULL, NULL, 0);
    if (rc != 0) {
        printf("TSS_Execute of TPM_CC_Create failed\n");
        goto exit_flush_primary;
    }
    printf("TSS_Execute of TPM_CC_Create is a success\n");

    /* Prepare for Loading Key */
    inLoad.parentHandle = outPrimary.objectHandle;
    inLoad.inPrivate = outCreate.outPrivate;
    inLoad.inPublic = outCreate.outPublic;
    /* Load Signing Key */
    rc = TSS_Execute(tssContext,
                (RESPONSE_PARAMETERS *)&outLoad,
                (COMMAND_PARAMETERS *)&inLoad,
                NULL, TPM_CC_Load,
                sessionHandle0, gStorageKeyAuth, sessionAttributes0,
                sessionHandle1, NULL, sessionAttributes1,
                sessionHandle2, NULL, sessionAttributes2,
                TPM_RH_NULL, NULL, 0);
    if (rc != 0) {
        printf("TSS_Execute of TPM_CC_Load failed\n");
        goto exit_flush_primary;
    }
    printf("TSS_Execute of TPM_CC_Load is a success\n");

exit_flush_all:

    inFlush.flushHandle = outLoad.objectHandle;
    rc = TSS_Execute(tssContext, NULL,
                (COMMAND_PARAMETERS *)&inFlush,
                NULL, TPM_CC_FlushContext,
                TPM_RH_NULL, NULL, 0);
    if (rc != 0) {
        printf("Signing key flushed from TPM\n");
    }

exit_flush_primary:

    inFlush.flushHandle = outPrimary.objectHandle;
    rc = TSS_Execute(tssContext, NULL,
                (COMMAND_PARAMETERS *)&inFlush,
                NULL, TPM_CC_FlushContext,
                TPM_RH_NULL, NULL, 0);
    if (rc != 0) {
        printf("Primary key flushed from TPM\n");
    }

exit:

    TSS_Delete(tssContext);
    printf("TSS_Delete executed\n");

    return rc;
}
