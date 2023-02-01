#include <cstddef>
#include <cstdint>

#define DNCP_DEFINE_GUID
#include <dncp.h>

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        EXTERN_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

// Define the IMetaDataImport IID here - cor.h provides the declaration.
MIDL_DEFINE_GUID(IID, IID_IMetaDataDispenser,0x809c652e,0x7396,0x11d2,0x97,0x71,0x00,0xa0,0xc9,0xb4,0xd5,0x0c);
MIDL_DEFINE_GUID(IID, IID_IMetaDataImport,0x7dac8207,0xd3ae,0x4c75,0x9b,0x67,0x92,0x80,0x1a,0x49,0x7d,0x44);
MIDL_DEFINE_GUID(IID, IID_IMetaDataImport2,0xfce5efa0,0x8bba,0x4f8e,0xa0,0x36,0x8f,0x20,0x22,0xb0,0x84,0x66);