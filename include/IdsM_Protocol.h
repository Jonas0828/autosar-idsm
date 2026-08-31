#pragma once
#include "IdsM_Types.h"

/* IDS Message serializer per FO PRS Intrusion Detection System Protocol
   (R24-11, Doc ID 981) §5.1. Converts a QSEv into the wire format:
     Event Frame (8B, mandatory) | Timestamp (8B, optional)
     | Context Data Frame (optional) | Signature Frame (optional, P2)
   All multi-byte fields are big-endian [PRS_Ids_00004]. */

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol version 2: context data carries a Context Data Version [PRS_Ids_00008] */
#define IDSM_PROTOCOL_VERSION            2u

/* Event Frame fixed size [PRS_Ids_00006] */
#define IDSM_IDS_EVENT_FRAME_SIZE        8u
#define IDSM_IDS_TIMESTAMP_SIZE          8u

/* Context Data Length encoding threshold: sizes 1..127 use the short (7 bit)
   form, larger sizes the long (31 bit, 4 byte) form [PRS §5.1.6] */
#define IDSM_IDS_CONTEXT_SHORT_MAX       127u

/* Protocol Header bits in Event Frame byte 0 [PRS_Ids_00009] */
#define IDSM_IDS_HEADER_CONTEXT_DATA     0x01u
#define IDSM_IDS_HEADER_TIMESTAMP        0x02u
#define IDSM_IDS_HEADER_SIGNATURE        0x04u

/* Total serialized size of the IDS Message for this QSEv (signature excluded). */
uint16 IdsM_Protocol_GetMessageSize(const IdsM_QualifiedSecurityEventType* qsev);

/* Serialize the QSEv into buffer (big-endian IDS Message).
   Returns the number of bytes written, or 0 on invalid input / too small buffer. */
uint16 IdsM_Protocol_SerializeQSEv(const IdsM_QualifiedSecurityEventType* qsev,
                                   uint8* buffer, uint16 buffer_size);

#ifdef __cplusplus
}
#endif
