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
MIDL_DEFINE_GUID(IID, IID_IMetaDataAssemblyImport,0xee62470b,0xe94b,0x424e,0x9b,0x7c,0x2f,0x00,0xc9,0x24,0x9f,0x93);
MIDL_DEFINE_GUID(IID, IID_IMetaDataEmit, 0xba3fee4c, 0xecb9, 0x4e41, 0x83, 0xb7, 0x18, 0x3f, 0xa4, 0x1c, 0xd8, 0x59);
MIDL_DEFINE_GUID(IID, IID_IMetaDataEmit2, 0xf5dd9950, 0xf693, 0x42e6, 0x83, 0xe, 0x7b, 0x83, 0x3e, 0x81, 0x46, 0xa9);

// Define an IID for our own marker interface
MIDL_DEFINE_GUID(IID, IID_IDNMDOwner, 0x250ebc02, 0x1a92, 0x4638, 0xaa, 0x6c, 0x3d, 0x0f, 0x98, 0xb3, 0xa6, 0xfb);
