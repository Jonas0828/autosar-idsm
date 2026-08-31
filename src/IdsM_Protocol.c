#include "IdsM_Protocol.h"
#include <stddef.h>   /* NULL */

/* ============================================================
   IDS Message serializer (FO PRS IDS Protocol, R24-11)

   Event Frame (8 bytes) [PRS_Ids_00006]:
     Byte0    ProtocolVersion(4bit) | ProtocolHeader(4bit)
              Header bit0 = Context Data Frame included
              Header bit1 = Timestamp included
              Header bit2 = Signature Frame included
     Byte1-2  IdsM Instance ID(10bit) | Sensor Instance ID(6bit)
     Byte3-4  Event Definition ID (16 bit)
     Byte5-6  Count (16 bit)
     Byte7    Reserved (0)

   Timestamp (8 bytes, optional) [PRS §5.1.5]:
     Byte0    Source(bit7) | Nanoseconds bit29..24
     Byte1-3  Nanoseconds bit23..0
     Byte4-7  Seconds (32 bit)

   Context Data Frame (optional) [PRS §5.1.6]:
     Byte0-1  Context Data Version (Byte0 bit7 = modified by callout)
     Length   7 bit short form (1 byte) if <= 127, else 31 bit long form (4 bytes)
     Bytes    context data blob

   Byte order: big-endian [PRS_Ids_00004].
   ============================================================ */

static uint16 context_length_field_size(uint16 context_size) {
    return (context_size <= IDSM_IDS_CONTEXT_SHORT_MAX) ? 1u : 4u;
}

uint16 IdsM_Protocol_GetMessageSize(const IdsM_QualifiedSecurityEventType* qsev) {
    uint16 size;
    boolean has_context;

    if (qsev == NULL) return 0u;

    has_context = (qsev->context_data != NULL) && (qsev->context_data_size > 0u);

    size = IDSM_IDS_EVENT_FRAME_SIZE;
    if (qsev->has_timestamp) {
        size = (uint16)(size + IDSM_IDS_TIMESTAMP_SIZE);
    }
    if (has_context) {
        /* 2 bytes Context Data Version + length field + blob */
        size = (uint16)(size + 2u + context_length_field_size(qsev->context_data_size)
                        + qsev->context_data_size);
    }
    return size;
}

uint16 IdsM_Protocol_SerializeQSEv(const IdsM_QualifiedSecurityEventType* qsev,
                                   uint8* buffer, uint16 buffer_size) {
    uint16 offset = 0u;
    uint16 required;
    uint8  header;
    boolean has_context;
    uint32 ns30;

    if ((qsev == NULL) || (buffer == NULL)) return 0u;

    required = IdsM_Protocol_GetMessageSize(qsev);
    if ((required == 0u) || (buffer_size < required)) return 0u;

    /* Signature not yet supported (P2) */
    has_context = (qsev->context_data != NULL) && (qsev->context_data_size > 0u);

    header = 0u;
    if (has_context)            header |= IDSM_IDS_HEADER_CONTEXT_DATA;
    if (qsev->has_timestamp)    header |= IDSM_IDS_HEADER_TIMESTAMP;

    /* ── Event Frame ── */
    buffer[offset++] = (uint8)((IDSM_PROTOCOL_VERSION << 4) | header);           /* Byte0 */
    buffer[offset++] = (uint8)(qsev->idsm_instance_id >> 2);                     /* Byte1: IdsM ID bit9..2 */
    buffer[offset++] = (uint8)(((uint16)(qsev->idsm_instance_id & 0x03u) << 6)
                               | (qsev->sensor_instance_id & 0x3Fu));            /* Byte2 */
    buffer[offset++] = (uint8)(qsev->external_event_id >> 8);                    /* Byte3 */
    buffer[offset++] = (uint8)(qsev->external_event_id & 0xFFu);                 /* Byte4 */
    buffer[offset++] = (uint8)(qsev->count >> 8);                                /* Byte5 */
    buffer[offset++] = (uint8)(qsev->count & 0xFFu);                             /* Byte6 */
    buffer[offset++] = 0u;                                                       /* Byte7 reserved */

    /* ── Timestamp (optional) ── */
    if (qsev->has_timestamp) {
        ns30 = qsev->timestamp.nanoseconds & 0x3FFFFFFFu;   /* 30 bit */
        buffer[offset++] = (uint8)(((qsev->timestamp.source == IDSM_TIMESTAMP_SOURCE_OEM)
                                        ? 0x80u : 0x00u)
                                   | ((ns30 >> 24) & 0x3Fu));
        buffer[offset++] = (uint8)((ns30 >> 16) & 0xFFu);
        buffer[offset++] = (uint8)((ns30 >> 8) & 0xFFu);
        buffer[offset++] = (uint8)(ns30 & 0xFFu);
        buffer[offset++] = (uint8)(qsev->timestamp.seconds >> 24);
        buffer[offset++] = (uint8)((qsev->timestamp.seconds >> 16) & 0xFFu);
        buffer[offset++] = (uint8)((qsev->timestamp.seconds >> 8) & 0xFFu);
        buffer[offset++] = (uint8)(qsev->timestamp.seconds & 0xFFu);
    }

    /* ── Context Data Frame (optional) ── */
    if (has_context) {
        uint16 i;
        buffer[offset++] = (uint8)(qsev->context_data_version >> 8);   /* bit7: callout flag */
        buffer[offset++] = (uint8)(qsev->context_data_version & 0xFFu);

        if (qsev->context_data_size <= IDSM_IDS_CONTEXT_SHORT_MAX) {
            buffer[offset++] = (uint8)qsev->context_data_size;          /* 7 bit short form */
        } else {
            uint32 len = qsev->context_data_size;
            buffer[offset++] = (uint8)(0x80u | ((len >> 24) & 0x7Fu));  /* 31 bit long form */
            buffer[offset++] = (uint8)((len >> 16) & 0xFFu);
            buffer[offset++] = (uint8)((len >> 8) & 0xFFu);
            buffer[offset++] = (uint8)(len & 0xFFu);
        }

        for (i = 0u; i < qsev->context_data_size; ++i) {
            buffer[offset++] = qsev->context_data[i];
        }
    }

    return offset;
}
